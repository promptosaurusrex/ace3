import base64


from hunt_compiler import compile_hunt


class TestCompileSimpleHunt:
    def test_collects_yaml_and_query_file(self, simple_hunt, hunt_dir):
        compiled = compile_hunt(str(simple_hunt), root_dir=str(hunt_dir))

        assert compiled.target == "hunts/test/test.yaml"
        assert compiled.root_dir == str(hunt_dir)
        assert len(compiled.yaml_files) == 1
        assert compiled.yaml_files[0].path == "hunts/test/test.yaml"

        assert len(compiled.query_files) == 1
        assert compiled.query_files[0].path == "hunts/test/test.query"
        assert "index=proxy" in compiled.query_files[0].content

    def test_no_executables_or_inline_includes(self, simple_hunt, hunt_dir):
        compiled = compile_hunt(str(simple_hunt), root_dir=str(hunt_dir))
        assert compiled.executable_files == []
        assert compiled.query_inline_includes == []


class TestCompileHuntWithIncludes:
    def test_collects_include_files(self, hunt_with_includes, hunt_dir):
        compiled = compile_hunt(str(hunt_with_includes), root_dir=str(hunt_dir))

        assert len(compiled.yaml_files) == 2
        paths = {f.path for f in compiled.yaml_files}
        assert "hunts/test/with_includes.yaml" in paths
        assert "hunts/includes/defaults.include.yaml" in paths

    def test_inline_query_no_query_file(self, hunt_with_includes, hunt_dir):
        compiled = compile_hunt(str(hunt_with_includes), root_dir=str(hunt_dir))
        assert compiled.query_files == []


class TestCompileHuntWithQueryIncludes:
    def test_collects_query_inline_includes(self, hunt_with_query_includes, hunt_dir):
        compiled = compile_hunt(str(hunt_with_query_includes), root_dir=str(hunt_dir))

        assert len(compiled.query_files) == 1
        assert len(compiled.query_inline_includes) == 1
        assert compiled.query_inline_includes[0].path == "hunts/test/ips.txt"
        assert "1.1.1.1" in compiled.query_inline_includes[0].content


class TestCompileHuntWithExecutables:
    def test_collects_predefined_executable(self, hunt_with_executables, hunt_dir):
        compiled = compile_hunt(str(hunt_with_executables), root_dir=str(hunt_dir))

        assert len(compiled.executable_files) == 1
        exe = compiled.executable_files[0]
        assert exe.path == "hunts/scripts/check_user.py"
        assert "#!/usr/bin/env python3" in exe.content
        assert exe.permissions == 0o755

    def test_collects_yaml_includes(self, hunt_with_executables, hunt_dir):
        compiled = compile_hunt(str(hunt_with_executables), root_dir=str(hunt_dir))

        paths = {f.path for f in compiled.yaml_files}
        assert "hunts/test/with_executables.yaml" in paths
        assert "hunts/commands/test_commands.include.yaml" in paths

    def test_collects_inline_executable(self, hunt_with_inline_executable, hunt_dir):
        compiled = compile_hunt(str(hunt_with_inline_executable), root_dir=str(hunt_dir))

        assert len(compiled.executable_files) == 1
        exe = compiled.executable_files[0]
        assert exe.path == "hunts/scripts/enrich.py"
        assert exe.permissions == 0o700


class TestCompileHuntWithSupportingFiles:
    def test_collects_supporting_files(self, hunt_with_supporting_files, hunt_dir):
        compiled = compile_hunt(str(hunt_with_supporting_files), root_dir=str(hunt_dir))

        exe_paths = {e.path for e in compiled.executable_files}
        assert "hunts/scripts/ip_ranges.json" in exe_paths

    def test_collects_executable_and_supporting_files(self, hunt_with_supporting_files, hunt_dir):
        compiled = compile_hunt(str(hunt_with_supporting_files), root_dir=str(hunt_dir))

        exe_paths = {e.path for e in compiled.executable_files}
        assert "hunts/scripts/check_ip.py" in exe_paths
        assert "hunts/scripts/ip_ranges.json" in exe_paths
        assert len(compiled.executable_files) == 2

    def test_inline_executable_with_files(self, hunt_dir):
        """Supporting files on inline executable commands are collected."""
        scripts_dir = hunt_dir / "hunts" / "scripts"
        scripts_dir.mkdir(parents=True)

        script = scripts_dir / "lookup.py"
        script.write_text("#!/usr/bin/env python3\nprint('ok')\n")
        script.chmod(0o755)

        data_file = scripts_dir / "data.csv"
        data_file.write_text("col1,col2\na,b\n")

        hunt_file = hunt_dir / "hunts" / "test" / "inline_files.yaml"
        hunt_file.parent.mkdir(parents=True, exist_ok=True)
        hunt_file.write_text(
            "rule:\n"
            "  uuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n"
            "  enabled: yes\n"
            "  name: inline_files_test\n"
            "  description: Inline exec with files\n"
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
            f"            path: {hunt_dir}/hunts/scripts/lookup.py\n"
            "            files:\n"
            f"              - {hunt_dir}/hunts/scripts/data.csv\n"
        )

        compiled = compile_hunt(str(hunt_file), root_dir=str(hunt_dir))

        exe_paths = {e.path for e in compiled.executable_files}
        assert "hunts/scripts/lookup.py" in exe_paths
        assert "hunts/scripts/data.csv" in exe_paths


class TestCompileHuntWithRelativePaths:
    def test_resolves_relative_predefined_command_path(self, hunt_with_relative_executable_paths, hunt_dir):
        compiled = compile_hunt(str(hunt_with_relative_executable_paths), root_dir=str(hunt_dir))

        assert len(compiled.executable_files) == 1
        exe = compiled.executable_files[0]
        assert exe.path == "hunts/scripts/check_user.py"
        assert "#!/usr/bin/env python3" in exe.content
        assert exe.permissions == 0o755

    def test_resolves_relative_supporting_files(self, hunt_with_relative_supporting_files, hunt_dir):
        compiled = compile_hunt(str(hunt_with_relative_supporting_files), root_dir=str(hunt_dir))

        exe_paths = {e.path for e in compiled.executable_files}
        assert "hunts/scripts/check_ip.py" in exe_paths
        assert "hunts/scripts/ip_ranges.json" in exe_paths
        assert len(compiled.executable_files) == 2

    def test_resolves_relative_inline_executable(self, hunt_with_relative_inline_executable, hunt_dir):
        compiled = compile_hunt(str(hunt_with_relative_inline_executable), root_dir=str(hunt_dir))

        assert len(compiled.executable_files) == 1
        exe = compiled.executable_files[0]
        assert exe.path == "hunts/scripts/enrich.py"
        assert exe.permissions == 0o700

    def test_relative_paths_resolved_in_yaml_content(self, hunt_with_relative_executable_paths, hunt_dir):
        """Stored YAML content should have absolute paths for the loader rewrite to work."""
        compiled = compile_hunt(str(hunt_with_relative_executable_paths), root_dir=str(hunt_dir))

        for yf in compiled.yaml_files:
            assert "../scripts/" not in yf.content

    def test_absolute_paths_still_work(self, hunt_with_executables, hunt_dir):
        """Existing absolute path behavior should be unchanged."""
        compiled = compile_hunt(str(hunt_with_executables), root_dir=str(hunt_dir))

        assert len(compiled.executable_files) == 1
        exe = compiled.executable_files[0]
        assert exe.path == "hunts/scripts/check_user.py"


class TestCompileHuntWithNestedConditions:
    def test_finds_executables_in_else_branch(self, hunt_dir):
        """Executables in else branches of conditions should be discovered."""
        scripts_dir = hunt_dir / "hunts" / "scripts"
        scripts_dir.mkdir(parents=True)

        script1 = scripts_dir / "script_a.py"
        script1.write_text("#!/usr/bin/env python3\nprint('a')\n")
        script1.chmod(0o755)

        script2 = scripts_dir / "script_b.py"
        script2.write_text("#!/usr/bin/env python3\nprint('b')\n")
        script2.chmod(0o755)

        hunt_file = hunt_dir / "hunts" / "test" / "nested.yaml"
        hunt_file.parent.mkdir(parents=True, exist_ok=True)
        hunt_file.write_text(
            "rule:\n"
            "  uuid: 66666666-6666-6666-6666-666666666666\n"
            "  enabled: yes\n"
            "  name: nested_test\n"
            "  description: Nested conditions\n"
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
            "      - when: '{{ _event.field1 }}'\n"
            "        execute:\n"
            "          - transform:\n"
            "              type: event\n"
            "              method: property\n"
            "              property_name: result_a\n"
            "              property_type: str\n"
            "              command:\n"
            "                type: executable\n"
            f"                path: {hunt_dir}/hunts/scripts/script_a.py\n"
            "        else:\n"
            "          - transform:\n"
            "              type: event\n"
            "              method: property\n"
            "              property_name: result_b\n"
            "              property_type: str\n"
            "              command:\n"
            "                type: executable\n"
            f"                path: {hunt_dir}/hunts/scripts/script_b.py\n"
        )

        compiled = compile_hunt(str(hunt_file), root_dir=str(hunt_dir))

        assert len(compiled.executable_files) == 2
        exe_paths = {e.path for e in compiled.executable_files}
        assert "hunts/scripts/script_a.py" in exe_paths
        assert "hunts/scripts/script_b.py" in exe_paths


class TestCompileHuntWithBinaryExecutable:
    def test_binary_executable_uses_base64_encoding(self, hunt_with_binary_executable, hunt_dir):
        hunt_file, original_bytes = hunt_with_binary_executable
        compiled = compile_hunt(str(hunt_file), root_dir=str(hunt_dir))

        assert len(compiled.executable_files) == 1
        exe = compiled.executable_files[0]
        assert exe.path == "hunts/scripts/lookup"
        assert exe.encoding == "base64"
        assert exe.permissions == 0o755
        assert base64.b64decode(exe.content) == original_bytes

    def test_text_executables_remain_text_encoding(self, hunt_with_inline_executable, hunt_dir):
        compiled = compile_hunt(str(hunt_with_inline_executable), root_dir=str(hunt_dir))

        exe = compiled.executable_files[0]
        assert exe.encoding == "text"
        assert "#!/usr/bin/env python3" in exe.content


class TestCompileHuntEdgeCases:
    def test_no_query_file(self, hunt_dir):
        """Hunt with inline query and no search: field."""
        hunt_file = hunt_dir / "test.yaml"
        hunt_file.write_text(
            "rule:\n"
            "  uuid: 77777777-7777-7777-7777-777777777777\n"
            "  enabled: yes\n"
            "  name: inline_query\n"
            "  description: Inline query\n"
            "  type: splunk\n"
            "  alert_type: test\n"
            "  frequency: '00:01:00'\n"
            "  time_range: '00:01:00'\n"
            "  max_time_range: '01:00:00'\n"
            "  full_coverage: yes\n"
            "  use_index_time: yes\n"
            "  query: 'index=main'\n"
        )
        compiled = compile_hunt(str(hunt_file), root_dir=str(hunt_dir))
        assert compiled.query_files == []
        assert compiled.query_inline_includes == []

    def test_circular_includes_handled(self, hunt_dir):
        """Circular YAML includes should not cause infinite recursion."""
        hunts = hunt_dir / "hunts"
        hunts.mkdir()

        file_a = hunts / "a.yaml"
        file_b = hunts / "b.yaml"

        file_a.write_text(
            "include:\n"
            "  - b.yaml\n"
            "rule:\n"
            "  uuid: a\n"
            "  name: a\n"
        )
        file_b.write_text(
            "include:\n"
            "  - a.yaml\n"
            "rule:\n"
            "  uuid: b\n"
            "  name: b\n"
        )

        compiled = compile_hunt(str(file_a), root_dir=str(hunt_dir))
        assert len(compiled.yaml_files) == 2

    def test_json_roundtrip(self, simple_hunt, hunt_dir):
        """Compile -> JSON -> deserialize produces equivalent object."""
        compiled = compile_hunt(str(simple_hunt), root_dir=str(hunt_dir))
        json_str = compiled.model_dump_json()
        restored = compile_hunt.__class__  # just to make it clear we're using the model
        restored = type(compiled).model_validate_json(json_str)
        assert restored == compiled
