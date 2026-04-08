import os
import stat


from hunt_compiler import compile_hunt, load_compiled_hunt, CompiledHunt


class TestLoadCompiledHunt:
    def test_writes_yaml_files(self, simple_hunt, hunt_dir, tmp_path):
        compiled = compile_hunt(str(simple_hunt), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        target_path = load_compiled_hunt(compiled, str(target_dir))

        assert os.path.isfile(target_path)
        assert target_path == str(target_dir / "hunts" / "test" / "test.yaml")

        with open(target_path) as f:
            content = f.read()
        assert "simple_test" in content

    def test_writes_query_files(self, simple_hunt, hunt_dir, tmp_path):
        compiled = compile_hunt(str(simple_hunt), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        query_path = target_dir / "hunts" / "test" / "test.query"
        assert query_path.is_file()
        assert "index=proxy" in query_path.read_text()

    def test_writes_include_files(self, hunt_with_includes, hunt_dir, tmp_path):
        compiled = compile_hunt(str(hunt_with_includes), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        defaults_path = target_dir / "hunts" / "includes" / "defaults.include.yaml"
        assert defaults_path.is_file()
        assert "default_tag" in defaults_path.read_text()

    def test_writes_query_inline_includes(self, hunt_with_query_includes, hunt_dir, tmp_path):
        compiled = compile_hunt(str(hunt_with_query_includes), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        ips_path = target_dir / "hunts" / "test" / "ips.txt"
        assert ips_path.is_file()
        assert "1.1.1.1" in ips_path.read_text()

    def test_writes_executables_with_permissions(self, hunt_with_inline_executable, hunt_dir, tmp_path):
        compiled = compile_hunt(str(hunt_with_inline_executable), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        script_path = target_dir / "hunts" / "scripts" / "enrich.py"
        assert script_path.is_file()
        assert "#!/usr/bin/env python3" in script_path.read_text()

        file_mode = stat.S_IMODE(os.stat(script_path).st_mode)
        assert file_mode == 0o700

    def test_rewrites_executable_paths_in_yaml(self, hunt_with_inline_executable, hunt_dir, tmp_path):
        compiled = compile_hunt(str(hunt_with_inline_executable), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        target_path = load_compiled_hunt(compiled, str(target_dir))

        with open(target_path) as f:
            yaml_content = f.read()

        # The original absolute path should be rewritten to the temp dir path
        original_abs_path = str(hunt_dir / "hunts" / "scripts" / "enrich.py")
        new_abs_path = str(target_dir / "hunts" / "scripts" / "enrich.py")

        assert original_abs_path not in yaml_content
        assert new_abs_path in yaml_content

    def test_rewrites_predefined_command_paths(self, hunt_with_executables, hunt_dir, tmp_path):
        compiled = compile_hunt(str(hunt_with_executables), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        # Check that the commands include file has rewritten paths
        commands_path = target_dir / "hunts" / "commands" / "test_commands.include.yaml"
        content = commands_path.read_text()

        original_abs_path = str(hunt_dir / "hunts" / "scripts" / "check_user.py")
        new_abs_path = str(target_dir / "hunts" / "scripts" / "check_user.py")

        assert original_abs_path not in content
        assert new_abs_path in content


class TestLoadBinaryExecutable:
    def test_writes_binary_executable(self, hunt_with_binary_executable, hunt_dir, tmp_path):
        hunt_file, original_bytes = hunt_with_binary_executable
        compiled = compile_hunt(str(hunt_file), root_dir=str(hunt_dir))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        binary_path = target_dir / "hunts" / "scripts" / "lookup"
        assert binary_path.is_file()
        assert binary_path.read_bytes() == original_bytes

        file_mode = stat.S_IMODE(os.stat(binary_path).st_mode)
        assert file_mode == 0o755


class TestRoundTrip:
    def test_compile_serialize_deserialize_load(self, simple_hunt, hunt_dir, tmp_path):
        """Full round-trip: compile -> JSON -> deserialize -> load."""
        compiled = compile_hunt(str(simple_hunt), root_dir=str(hunt_dir))
        json_str = compiled.model_dump_json()

        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        target_path = load_compiled_hunt(restored, str(target_dir))

        assert os.path.isfile(target_path)
        query_path = target_dir / "hunts" / "test" / "test.query"
        assert query_path.is_file()

    def test_compile_serialize_deserialize_load_with_executables(
        self, hunt_with_executables, hunt_dir, tmp_path
    ):
        """Round-trip with executable files preserves permissions."""
        compiled = compile_hunt(str(hunt_with_executables), root_dir=str(hunt_dir))
        json_str = compiled.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        load_compiled_hunt(restored, str(target_dir))

        script_path = target_dir / "hunts" / "scripts" / "check_user.py"
        assert script_path.is_file()
        file_mode = stat.S_IMODE(os.stat(script_path).st_mode)
        assert file_mode == 0o755

    def test_compile_serialize_deserialize_load_binary_executable(
        self, hunt_with_binary_executable, hunt_dir, tmp_path
    ):
        """Round-trip with binary executable preserves exact bytes and permissions."""
        hunt_file, original_bytes = hunt_with_binary_executable
        compiled = compile_hunt(str(hunt_file), root_dir=str(hunt_dir))
        json_str = compiled.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        load_compiled_hunt(restored, str(target_dir))

        binary_path = target_dir / "hunts" / "scripts" / "lookup"
        assert binary_path.is_file()
        assert binary_path.read_bytes() == original_bytes
        file_mode = stat.S_IMODE(os.stat(binary_path).st_mode)
        assert file_mode == 0o755
