import base64
import json

import pytest
from pydantic import ValidationError

from hunt_compiler.models import CompiledHunt, EmbeddedFile


class TestEmbeddedFile:
    def test_basic_fields(self):
        ef = EmbeddedFile(kind="yaml", path="hunts/test.yaml", content="rule:\n  name: test\n")
        assert ef.kind == "yaml"
        assert ef.path == "hunts/test.yaml"
        assert ef.content == "rule:\n  name: test\n"
        assert ef.encoding == "text"
        assert ef.permissions is None
        assert ef.original_abs is None

    def test_with_permissions(self):
        ef = EmbeddedFile(
            kind="executable",
            path="scripts/run.py",
            content="#!/usr/bin/env python3\n",
            permissions=0o755,
        )
        assert ef.permissions == 0o755
        assert ef.permissions == 493

    def test_base64_encoding(self):
        binary_data = b"\x7fELF\x00\x01\x02\x03"
        encoded = base64.b64encode(binary_data).decode("ascii")
        ef = EmbeddedFile(
            kind="executable",
            path="bin/lookup",
            content=encoded,
            encoding="base64",
            permissions=0o755,
        )
        assert ef.encoding == "base64"
        assert base64.b64decode(ef.content) == binary_data

    def test_original_abs_provenance(self):
        ef = EmbeddedFile(
            kind="yaml",
            path="hunts/test.yaml",
            content="content",
            original_abs="/author/machine/hunts/test.yaml",
        )
        assert ef.original_abs == "/author/machine/hunts/test.yaml"

    def test_json_roundtrip(self):
        ef = EmbeddedFile(
            kind="executable",
            path="test.py",
            content="print('hello')\n",
            permissions=0o755,
            original_abs="/author/test.py",
        )
        json_str = ef.model_dump_json()
        restored = EmbeddedFile.model_validate_json(json_str)
        assert restored == ef

    def test_json_roundtrip_base64(self):
        binary_data = b"\x7fELF\x00" + bytes(range(256))
        encoded = base64.b64encode(binary_data).decode("ascii")
        ef = EmbeddedFile(
            kind="executable",
            path="bin/tool",
            content=encoded,
            encoding="base64",
            permissions=0o755,
        )
        json_str = ef.model_dump_json()
        restored = EmbeddedFile.model_validate_json(json_str)
        assert restored == ef
        assert base64.b64decode(restored.content) == binary_data

    @pytest.mark.parametrize(
        "kind", ["yaml", "query", "query_include", "executable", "support"]
    )
    def test_accepted_kinds(self, kind):
        ef = EmbeddedFile(kind=kind, path="x", content="")
        assert ef.kind == kind

    def test_rejects_unknown_kind(self):
        with pytest.raises(ValidationError):
            EmbeddedFile(kind="something_else", path="x", content="")


class TestCompiledHunt:
    def test_minimal(self):
        ch = CompiledHunt(
            target="hunts/test.yaml",
            package_root="/opt/ace",
            assets=[EmbeddedFile(kind="yaml", path="hunts/test.yaml", content="rule:\n  name: test\n")],
        )
        assert ch.version == 2
        assert ch.target == "hunts/test.yaml"
        assert ch.package_root == "/opt/ace"
        assert len(ch.assets) == 1

    def test_default_version_is_2(self):
        ch = CompiledHunt(
            target="t.yaml",
            package_root="/tmp",
            assets=[EmbeddedFile(kind="yaml", path="t.yaml", content="")],
        )
        assert ch.version == 2

    def test_v1_payload_rejected(self):
        """Guard against back-compat creep: a legacy v1 payload should fail
        validation cleanly against the new model shape."""
        v1_payload = {
            "version": 1,
            "target": "hunts/test.yaml",
            "root_dir": "/opt/ace",
            "yaml_files": [{"path": "hunts/test.yaml", "content": "rule: {}"}],
            "query_files": [],
            "query_inline_includes": [],
            "executable_files": [],
        }
        with pytest.raises(ValidationError):
            CompiledHunt.model_validate(v1_payload)

    def test_json_roundtrip(self):
        ch = CompiledHunt(
            target="hunts/test.yaml",
            package_root="/opt/ace",
            assets=[
                EmbeddedFile(kind="yaml", path="hunts/test.yaml", content="yaml content"),
                EmbeddedFile(kind="query", path="hunts/test.query", content="index=main"),
                EmbeddedFile(
                    kind="executable",
                    path="scripts/run.py",
                    content="#!/usr/bin/env python3\n",
                    permissions=0o755,
                ),
            ],
        )
        json_str = ch.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)
        assert restored == ch
        executables = [a for a in restored.assets if a.kind == "executable"]
        assert executables[0].permissions == 0o755

    def test_json_is_valid_json(self):
        ch = CompiledHunt(
            target="test.yaml",
            package_root="/tmp",
            assets=[EmbeddedFile(kind="yaml", path="test.yaml", content="content")],
        )
        parsed = json.loads(ch.model_dump_json())
        assert parsed["version"] == 2
        assert parsed["target"] == "test.yaml"
        assert parsed["package_root"] == "/tmp"
