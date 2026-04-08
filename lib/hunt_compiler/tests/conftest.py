import os
import struct

import pytest


@pytest.fixture
def hunt_dir(tmp_path):
    """Create a minimal hunt directory structure for testing."""
    return tmp_path


@pytest.fixture
def simple_hunt(hunt_dir):
    """A simple hunt with an external query file."""
    query_file = hunt_dir / "hunts" / "test" / "test.query"
    query_file.parent.mkdir(parents=True)
    query_file.write_text("index=proxy src_ip=1.1.1.1\n")

    hunt_file = hunt_dir / "hunts" / "test" / "test.yaml"
    hunt_file.write_text(
        "rule:\n"
        "  uuid: 11111111-1111-1111-1111-111111111111\n"
        "  enabled: yes\n"
        "  name: simple_test\n"
        "  description: Simple test hunt\n"
        "  type: splunk\n"
        "  alert_type: test\n"
        "  frequency: '00:01:00'\n"
        "  time_range: '00:01:00'\n"
        "  max_time_range: '01:00:00'\n"
        "  full_coverage: yes\n"
        "  use_index_time: yes\n"
        "  search: hunts/test/test.query\n"
    )
    return hunt_file


@pytest.fixture
def hunt_with_includes(hunt_dir):
    """A hunt that uses YAML include directives."""
    includes_dir = hunt_dir / "hunts" / "includes"
    includes_dir.mkdir(parents=True)

    defaults_file = includes_dir / "defaults.include.yaml"
    defaults_file.write_text(
        "rule:\n"
        "  tags:\n"
        "    - default_tag\n"
        "  analysis_mode: correlation\n"
    )

    hunt_dir_path = hunt_dir / "hunts" / "test"
    hunt_dir_path.mkdir(parents=True, exist_ok=True)

    hunt_file = hunt_dir_path / "with_includes.yaml"
    hunt_file.write_text(
        "include:\n"
        "  - ../includes/defaults.include.yaml\n"
        "\n"
        "rule:\n"
        "  uuid: 22222222-2222-2222-2222-222222222222\n"
        "  enabled: yes\n"
        "  name: includes_test\n"
        "  description: Hunt with includes\n"
        "  type: splunk\n"
        "  alert_type: test\n"
        "  frequency: '00:01:00'\n"
        "  time_range: '00:01:00'\n"
        "  max_time_range: '01:00:00'\n"
        "  full_coverage: yes\n"
        "  use_index_time: yes\n"
        "  query: 'index=main src_ip=2.2.2.2'\n"
        "  tags:\n"
        "    - hunt_tag\n"
    )
    return hunt_file


@pytest.fixture
def hunt_with_query_includes(hunt_dir):
    """A hunt whose query file contains <include:path> directives."""
    ips_file = hunt_dir / "hunts" / "test" / "ips.txt"
    ips_file.parent.mkdir(parents=True)
    ips_file.write_text("1.1.1.1 OR 2.2.2.2")

    query_file = hunt_dir / "hunts" / "test" / "test_qi.query"
    query_file.write_text(
        f"index=proxy src_ip=<include:{hunt_dir}/hunts/test/ips.txt>\n"
    )

    hunt_file = hunt_dir / "hunts" / "test" / "test_qi.yaml"
    hunt_file.write_text(
        "rule:\n"
        "  uuid: 33333333-3333-3333-3333-333333333333\n"
        "  enabled: yes\n"
        "  name: query_includes_test\n"
        "  description: Hunt with query inline includes\n"
        "  type: splunk\n"
        "  alert_type: test\n"
        "  frequency: '00:01:00'\n"
        "  time_range: '00:01:00'\n"
        "  max_time_range: '01:00:00'\n"
        "  full_coverage: yes\n"
        "  use_index_time: yes\n"
        "  search: hunts/test/test_qi.query\n"
    )
    return hunt_file


@pytest.fixture
def hunt_with_executables(hunt_dir):
    """A hunt with correlation commands referencing executable scripts."""
    scripts_dir = hunt_dir / "hunts" / "scripts"
    scripts_dir.mkdir(parents=True)

    script_file = scripts_dir / "check_user.py"
    script_file.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('true')\n"
    )
    script_file.chmod(0o755)

    commands_dir = hunt_dir / "hunts" / "commands"
    commands_dir.mkdir(parents=True)

    commands_file = commands_dir / "test_commands.include.yaml"
    commands_file.write_text(
        "commands:\n"
        "  - name: check_user\n"
        "    type: executable\n"
        f"    path: {hunt_dir}/hunts/scripts/check_user.py\n"
        "    cache: 30d\n"
        '    args: ["--user", "{{{{ _event[\'user\'] }}}}"]\n'
    )

    hunt_dir_path = hunt_dir / "hunts" / "test"
    hunt_dir_path.mkdir(parents=True, exist_ok=True)

    hunt_file = hunt_dir_path / "with_executables.yaml"
    hunt_file.write_text(
        "include:\n"
        "  - ../commands/test_commands.include.yaml\n"
        "\n"
        "rule:\n"
        "  uuid: 44444444-4444-4444-4444-444444444444\n"
        "  enabled: yes\n"
        "  name: executables_test\n"
        "  description: Hunt with executable commands\n"
        "  type: splunk\n"
        "  alert_type: test\n"
        "  frequency: '00:01:00'\n"
        "  time_range: '00:01:00'\n"
        "  max_time_range: '01:00:00'\n"
        "  full_coverage: yes\n"
        "  use_index_time: yes\n"
        "  query: 'index=main user=*'\n"
        "  correlate:\n"
        "    logic:\n"
        "      - transform:\n"
        "          type: event\n"
        "          method: property\n"
        "          property_name: is_service\n"
        "          property_type: bool\n"
        "          command:\n"
        "            type: defined\n"
        "            name: check_user\n"
        "      - when: '{{ _event.is_service }}'\n"
        "        execute:\n"
        "          - action: filter\n"
    )
    return hunt_file


@pytest.fixture
def hunt_with_inline_executable(hunt_dir):
    """A hunt with an executable command defined inline in the correlate logic."""
    scripts_dir = hunt_dir / "hunts" / "scripts"
    scripts_dir.mkdir(parents=True)

    script_file = scripts_dir / "enrich.py"
    script_file.write_text(
        "#!/usr/bin/env python3\n"
        "print('{\"enriched\": true}')\n"
    )
    script_file.chmod(0o700)

    hunt_dir_path = hunt_dir / "hunts" / "test"
    hunt_dir_path.mkdir(parents=True, exist_ok=True)

    hunt_file = hunt_dir_path / "inline_exec.yaml"
    hunt_file.write_text(
        "rule:\n"
        "  uuid: 55555555-5555-5555-5555-555555555555\n"
        "  enabled: yes\n"
        "  name: inline_exec_test\n"
        "  description: Hunt with inline executable\n"
        "  type: splunk\n"
        "  alert_type: test\n"
        "  frequency: '00:01:00'\n"
        "  time_range: '00:01:00'\n"
        "  max_time_range: '01:00:00'\n"
        "  full_coverage: yes\n"
        "  use_index_time: yes\n"
        "  query: 'index=main'\n"
        "  correlate:\n"
        "    logic:\n"
        "      - transform:\n"
        "          type: event\n"
        "          method: property\n"
        "          property_name: enriched\n"
        "          property_type: dict\n"
        "          command:\n"
        "            type: executable\n"
        f"            path: {hunt_dir}/hunts/scripts/enrich.py\n"
    )
    return hunt_file


@pytest.fixture
def hunt_with_binary_executable(hunt_dir):
    """A hunt with a binary (non-text) executable command."""
    scripts_dir = hunt_dir / "hunts" / "scripts"
    scripts_dir.mkdir(parents=True)

    # Write a minimal ELF-like binary (just needs to be non-text)
    binary_file = scripts_dir / "lookup"
    elf_header = b"\x7fELF" + b"\x00" * 12  # ELF magic + padding
    binary_content = elf_header + struct.pack("<I", 42) + os.urandom(64)
    binary_file.write_bytes(binary_content)
    binary_file.chmod(0o755)

    hunt_dir_path = hunt_dir / "hunts" / "test"
    hunt_dir_path.mkdir(parents=True, exist_ok=True)

    hunt_file = hunt_dir_path / "binary_exec.yaml"
    hunt_file.write_text(
        "rule:\n"
        "  uuid: 88888888-8888-8888-8888-888888888888\n"
        "  enabled: yes\n"
        "  name: binary_exec_test\n"
        "  description: Hunt with binary executable\n"
        "  type: splunk\n"
        "  alert_type: test\n"
        "  frequency: '00:01:00'\n"
        "  time_range: '00:01:00'\n"
        "  max_time_range: '01:00:00'\n"
        "  full_coverage: yes\n"
        "  use_index_time: yes\n"
        "  query: 'index=main'\n"
        "  correlate:\n"
        "    logic:\n"
        "      - transform:\n"
        "          type: event\n"
        "          method: property\n"
        "          property_name: result\n"
        "          property_type: str\n"
        "          command:\n"
        "            type: executable\n"
        f"            path: {hunt_dir}/hunts/scripts/lookup\n"
    )
    return hunt_file, binary_content
