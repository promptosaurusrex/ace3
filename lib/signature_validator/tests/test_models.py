import base64
import json


from hunt_compiler.models import CompiledHunt, EmbeddedFile


class TestEmbeddedFile:
    def test_basic_fields(self):
        ef = EmbeddedFile(path="hunts/test.yaml", content="rule:\n  name: test\n")
        assert ef.path == "hunts/test.yaml"
        assert ef.content == "rule:\n  name: test\n"
        assert ef.encoding == "text"
        assert ef.permissions is None

    def test_with_permissions(self):
        ef = EmbeddedFile(path="scripts/run.py", content="#!/usr/bin/env python3\n", permissions=0o755)
        assert ef.permissions == 0o755
        assert ef.permissions == 493

    def test_base64_encoding(self):
        binary_data = b"\x7fELF\x00\x01\x02\x03"
        encoded = base64.b64encode(binary_data).decode("ascii")
        ef = EmbeddedFile(path="bin/lookup", content=encoded, encoding="base64", permissions=0o755)
        assert ef.encoding == "base64"
        assert base64.b64decode(ef.content) == binary_data

    def test_json_roundtrip(self):
        ef = EmbeddedFile(path="test.py", content="print('hello')\n", permissions=0o755)
        json_str = ef.model_dump_json()
        restored = EmbeddedFile.model_validate_json(json_str)
        assert restored == ef

    def test_json_roundtrip_base64(self):
        binary_data = b"\x7fELF\x00" + bytes(range(256))
        encoded = base64.b64encode(binary_data).decode("ascii")
        ef = EmbeddedFile(path="bin/tool", content=encoded, encoding="base64", permissions=0o755)
        json_str = ef.model_dump_json()
        restored = EmbeddedFile.model_validate_json(json_str)
        assert restored == ef
        assert base64.b64decode(restored.content) == binary_data


class TestCompiledHunt:
    def test_minimal(self):
        ch = CompiledHunt(
            target="hunts/test.yaml",
            root_dir="/opt/ace",
            yaml_files=[EmbeddedFile(path="hunts/test.yaml", content="rule:\n  name: test\n")],
        )
        assert ch.version == 1
        assert ch.target == "hunts/test.yaml"
        assert len(ch.yaml_files) == 1
        assert ch.query_files == []
        assert ch.query_inline_includes == []
        assert ch.executable_files == []

    def test_json_roundtrip(self):
        ch = CompiledHunt(
            target="hunts/test.yaml",
            root_dir="/opt/ace",
            yaml_files=[EmbeddedFile(path="hunts/test.yaml", content="yaml content")],
            query_files=[EmbeddedFile(path="hunts/test.query", content="index=main")],
            executable_files=[
                EmbeddedFile(path="scripts/run.py", content="#!/usr/bin/env python3\n", permissions=0o755)
            ],
        )
        json_str = ch.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)
        assert restored == ch
        assert restored.executable_files[0].permissions == 0o755

    def test_json_is_valid_json(self):
        ch = CompiledHunt(
            target="test.yaml",
            root_dir="/tmp",
            yaml_files=[EmbeddedFile(path="test.yaml", content="content")],
        )
        parsed = json.loads(ch.model_dump_json())
        assert parsed["version"] == 1
        assert parsed["target"] == "test.yaml"
