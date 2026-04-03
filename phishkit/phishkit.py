#!/usr/bin/env python3

#
# NOTE this is external to ACE so it doesn't use the saq namespace
#

import argparse
import json
import logging
import mimetypes
import os
from subprocess import PIPE, Popen, TimeoutExpired
import uuid
from celery import Celery
import shutil
from yaml import load, SafeLoader
import magic

logger = logging.getLogger(__name__)

SHARED_CONFIG = "/phishkit/config/phishkit_config.yaml"


def _has_proxy_error(stdout: str, stderr: str, error_patterns: list[str]) -> bool:
    combined = (stdout or "") + (stderr or "")
    return any(pattern in combined for pattern in error_patterns)


def _has_proxy_status_code(output_dir: str, proxy_status_codes: list[int]) -> bool:
    """Check if the main page response in requests.json has a proxy error status code.

    The main page response is the first entry with type=="response" in requests.json.
    """
    if not proxy_status_codes:
        return False
    requests_path = os.path.join(output_dir, "requests.json")
    try:
        with open(requests_path, "r") as f:
            requests_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logger.debug("could not read requests.json from %s: %s", output_dir, e)
        return False

    for entry in requests_data:
        if entry.get("type") == "response":
            status_code = entry.get("status_code")
            if status_code in proxy_status_codes:
                logger.info(
                    "main page returned proxy error status %s in %s",
                    status_code, output_dir,
                )
                return True
            return False

    return False


def _sync_config(source_path: str | None) -> str | None:
    """Copy phishkit config to the shared phishkit volume.

    Returns the destination path inside the shared volume if successful, None otherwise.
    """
    if not source_path or not os.path.isfile(source_path):
        logger.info("no config found at %s", source_path)
        return None

    try:
        os.makedirs(os.path.dirname(SHARED_CONFIG), exist_ok=True)
        shutil.copy2(source_path, SHARED_CONFIG)
        logger.info("synced config %s to %s", source_path, SHARED_CONFIG)
        return SHARED_CONFIG
    except Exception as e:
        logger.warning("failed to sync config: %s", e)
        return None


def _run_scanner(
    target_args: list,
    output_dir: str,
    job_id: str,
    timeout: int,
    proxy: str | None,
    proxy_fallback_to_direct: bool,
    config_path: str,
) -> tuple:
    """Run the phishkit scanner, optionally retrying without proxy on proxy errors.

    Returns (stdout, stderr, returncode).
    """
    if not config_path:
        raise ValueError("config_path is required")
    abs_config = os.path.join("/opt/ace", config_path)
    if not os.path.isfile(abs_config):
        raise FileNotFoundError(f"phishkit config not found: {abs_config}")

    with open(abs_config, "r") as f:
        config = load(f, Loader=SafeLoader)
    proxy_fallback = config.get("proxy_fallback", {}) if isinstance(config, dict) else {}

    synced = _sync_config(abs_config)

    def build_cmd(use_proxy, out_dir):
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            "ace-phishkit:/phishkit",
            os.environ.get("ACE3_PHISHKIT_IMAGE_URL", "phishkit"),
            "/opt/venv/bin/python",
            "/opt/app/scanner.py",
            *target_args,
            "--output-dir",
            out_dir,
        ]
        if use_proxy and proxy:
            cmd.extend(["--proxy", proxy])
        if synced:
            cmd.extend(["--config", synced])
        return cmd

    cmd = build_cmd(use_proxy=True, out_dir=output_dir)
    process = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True)

    should_retry = False
    timed_out = False
    _stdout, _stderr = "", ""

    try:
        _stdout, _stderr = process.communicate(timeout=timeout)
    except TimeoutExpired:
        process.kill()
        process.wait()
        timed_out = True
        if proxy and proxy_fallback_to_direct and proxy_fallback.get("retry_on_timeout", False):
            should_retry = True
            logger.warning("timeout for job %s, retrying without proxy", job_id)
        else:
            raise

    if not timed_out:
        for line in _stdout.splitlines():
            logging.info(f"stdout> {line}")

        if process.returncode != 0:
            for line in _stderr.splitlines():
                logging.info(f"stderr> {line}")

        if proxy and proxy_fallback_to_direct:
            if _has_proxy_error(_stdout, _stderr, proxy_fallback.get("error_patterns", [])):
                should_retry = True
                logger.warning("proxy error detected for job %s, retrying without proxy", job_id)
            elif _has_proxy_status_code(output_dir, proxy_fallback.get("proxy_status_codes", [])):
                should_retry = True
                logger.warning("proxy error status code for job %s, retrying without proxy", job_id)

    if should_retry:
        proxy_stdout = _stdout

        retry_output_dir = f"{output_dir}-direct"
        os.makedirs(retry_output_dir, exist_ok=True)

        retry_cmd = build_cmd(use_proxy=False, out_dir=retry_output_dir)
        process = Popen(retry_cmd, stdout=PIPE, stderr=PIPE, text=True)
        try:
            _stdout, _stderr = process.communicate(timeout=timeout)
        except TimeoutExpired:
            process.kill()
            process.wait()
            raise

        for line in _stdout.splitlines():
            logging.info(f"stdout(direct)> {line}")

        if process.returncode != 0:
            for line in _stderr.splitlines():
                logging.info(f"stderr(direct)> {line}")

        reason = "timed out" if timed_out else "failed"
        _stdout = f"--- PROXY ATTEMPT ({reason}, retried direct) ---\n{proxy_stdout}\n--- DIRECT ATTEMPT ---\n{_stdout}"

        # copy retry output files into the main output directory
        for entry in os.listdir(retry_output_dir):
            src = os.path.join(retry_output_dir, entry)
            dst = os.path.join(output_dir, entry)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
            elif os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)

    with open(os.path.join(output_dir, "std.out"), "w") as fp:
        fp.write(_stdout)

    with open(os.path.join(output_dir, "std.err"), "w") as fp:
        fp.write(_stderr)

    with open(os.path.join(output_dir, "exit.code"), "w") as fp:
        fp.write(str(process.returncode))

    return _stdout, _stderr, process.returncode


if os.path.exists("/auth/passwords/redis"):
    with open("/auth/passwords/redis", "r") as fp:
        redis_password = fp.read().strip()
else:
    redis_password = ""

if os.path.exists("/auth/passwords/rabbitmq"):
    with open("/auth/passwords/rabbitmq", "r") as fp:
        rabbitmq_password = fp.read().strip()
else:
    rabbitmq_password = ""

app = Celery(
    "phishkit",
    backend=f"redis://ace3:{redis_password}@redis:6379/7",
    broker=f"pyamqp://ace3:{rabbitmq_password}@rabbitmq//")

app.conf.broker_transport_options = {"global_keyprefix": "phishkit"}

@app.task
def ping() -> str:
    return "pong"

def _process_output(job_id: str, output_dir: str) -> str:
    """Returns the output directory path for the completed scan job."""
    return output_dir

def _correct_file_extension(file_path: str) -> str:
    """Attempts to correct the file extension of the given file based on the mime type.
    If the file extension needs to change, the file is renamed and the new file path is returned.
    If the guess on the mime type or file extension fails, the original file path is returned.
    Otherwise, the original file path is returned."""

    mime_type = magic.from_file(file_path, mime=True)
    if not mime_type:
        return file_path

    logging.info(f"mime type: {mime_type} for {file_path}")

    file_extension = mimetypes.guess_extension(mime_type)
    if not file_extension:
        return file_path

    # NOTE file_extension already has a leading dot
    logging.info(f"file extension: {file_extension} for {file_path}")

    if file_path.lower().endswith(f"{file_extension.lower()}"):
        return file_path

    # create a new file path with the correct extension
    dir_path = os.path.dirname(file_path)
    file_name, _ = os.path.splitext(os.path.basename(file_path))
    new_file_path = f"{dir_path}/{file_name}{file_extension}"
    logging.info(f"correcting file extension from {file_path} to {new_file_path}")
    os.rename(file_path, new_file_path)
    return new_file_path

@app.task
def scan_file(file_path: str, timeout: int = 15, proxy: str = None, proxy_fallback_to_direct: bool = False, config_path: str = None) -> str:
    # create a place to put the file we're going to render in the browser
    job_id = str(uuid.uuid4())
    input_dir = f"/phishkit/input/{job_id}"
    output_dir = f"/phishkit/output/{job_id}"
    os.makedirs(input_dir)
    os.makedirs(output_dir)

    logger.info("started file job %s for %s", job_id, file_path)

    # copy the file into the job input directory
    target_file_path = f"{input_dir}/{os.path.basename(file_path)}"
    shutil.copy2(file_path, target_file_path)

    # correct the file extension
    target_file_path = _correct_file_extension(target_file_path)

    _run_scanner(
        target_args=["--file", target_file_path],
        output_dir=output_dir,
        job_id=job_id,
        timeout=timeout,
        proxy=proxy,
        proxy_fallback_to_direct=proxy_fallback_to_direct,
        config_path=config_path,
    )

    return _process_output(job_id, output_dir)

@app.task
def scan_url(url: str, timeout: int = 15, proxy: str = None, proxy_fallback_to_direct: bool = False, config_path: str = None) -> str:
    # create an output directory for the scan
    job_id = str(uuid.uuid4())
    output_dir = f"/phishkit/output/{job_id}"
    os.makedirs(output_dir)

    logger.info(f"started url job {job_id} for {url}")

    _stdout, _stderr, returncode = _run_scanner(
        target_args=[url],
        output_dir=output_dir,
        job_id=job_id,
        timeout=timeout,
        proxy=proxy,
        proxy_fallback_to_direct=proxy_fallback_to_direct,
        config_path=config_path,
    )

    if returncode != 0:
        raise Exception(f"scan failed: {_stderr}")

    return _process_output(job_id, output_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="Load celery configuration from this file.")
    args = parser.parse_args()

    if args.config:
        with open(args.config, "r") as f:
            config = load(f, Loader=SafeLoader)
            if config:
                app.conf.update(config)

    app.worker_main(
        [
            "worker",
            "--loglevel=INFO",
        ]
    )
