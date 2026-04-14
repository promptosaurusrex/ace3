import base64
import os

import pytest

from hunt_compiler import (
    CompiledHunt,
    OutOfPackageRootError,
    PackageRootNotFound,
    compile_hunt,
    find_package_root,
)
from hunt_compiler.compiler import PKG_TOKEN


def _by_kind(compiled, kind):
    return [a for a in compiled.assets if a.kind == kind]


class TestCompileSimpleHunt:
    def test_collects_yaml_and_query_file(self, simple_hunt, hunt_dir):
        compiled = compile_hunt(str(simple_hunt))

        assert compiled.version == 2
        assert compiled.target == "hunts/test/test.yaml"
        assert compiled.package_root == str(hunt_dir)

        yaml_assets = _by_kind(compiled, "yaml")
        assert len(yaml_assets) == 1
        assert yaml_assets[0].path == "hunts/test/test.yaml"

        query_assets = _by_kind(compiled, "query")
        assert len(query_assets) == 1
        assert query_assets[0].path == "hunts/test/test.query"
        assert "index=proxy" in query_assets[0].content

    def test_no_executables_or_inline_includes(self, simple_hunt):
        compiled = compile_hunt(str(simple_hunt))
        assert _by_kind(compiled, "executable") == []
        assert _by_kind(compiled, "query_include") == []


class TestCompileHuntWithIncludes:
    def test_collects_include_files(self, hunt_with_includes):
        compiled = compile_hunt(str(hunt_with_includes))

        yaml_assets = _by_kind(compiled, "yaml")
        assert len(yaml_assets) == 2
        paths = {f.path for f in yaml_assets}
        assert "hunts/test/with_includes.yaml" in paths
        assert "hunts/includes/defaults.include.yaml" in paths

    def test_inline_query_no_query_file(self, hunt_with_includes):
        compiled = compile_hunt(str(hunt_with_includes))
        assert _by_kind(compiled, "query") == []


class TestCompileHuntWithQueryIncludes:
    def test_collects_query_inline_includes(self, hunt_with_query_includes):
        compiled = compile_hunt(str(hunt_with_query_includes))

        assert len(_by_kind(compiled, "query")) == 1
        include_assets = _by_kind(compiled, "query_include")
        assert len(include_assets) == 1
        assert include_assets[0].path == "hunts/test/ips.txt"
        assert "1.1.1.1" in include_assets[0].content


class TestCompileHuntWithExecutables:
    def test_collects_predefined_executable(self, hunt_with_executables):
        compiled = compile_hunt(str(hunt_with_executables))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        exe = executables[0]
        assert exe.path == "hunts/scripts/check_user.py"
        assert "#!/usr/bin/env python3" in exe.content
        assert exe.permissions == 0o755

    def test_collects_yaml_includes(self, hunt_with_executables):
        compiled = compile_hunt(str(hunt_with_executables))

        paths = {f.path for f in _by_kind(compiled, "yaml")}
        assert "hunts/test/with_executables.yaml" in paths
        assert "hunts/commands/test_commands.include.yaml" in paths

    def test_collects_inline_executable(self, hunt_with_inline_executable):
        compiled = compile_hunt(str(hunt_with_inline_executable))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        exe = executables[0]
        assert exe.path == "hunts/scripts/enrich.py"
        assert exe.permissions == 0o700


class TestCompileHuntWithSupportingFiles:
    def test_collects_supporting_files(self, hunt_with_supporting_files):
        compiled = compile_hunt(str(hunt_with_supporting_files))

        support_paths = {a.path for a in _by_kind(compiled, "support")}
        assert "hunts/scripts/ip_ranges.json" in support_paths

    def test_collects_executable_and_supporting_files(self, hunt_with_supporting_files):
        compiled = compile_hunt(str(hunt_with_supporting_files))

        exe_paths = {a.path for a in _by_kind(compiled, "executable")}
        support_paths = {a.path for a in _by_kind(compiled, "support")}
        assert "hunts/scripts/check_ip.py" in exe_paths
        assert "hunts/scripts/ip_ranges.json" in support_paths

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

        compiled = compile_hunt(str(hunt_file))

        exe_paths = {a.path for a in _by_kind(compiled, "executable")}
        support_paths = {a.path for a in _by_kind(compiled, "support")}
        assert "hunts/scripts/lookup.py" in exe_paths
        assert "hunts/scripts/data.csv" in support_paths


class TestCompileHuntWithRelativePaths:
    def test_resolves_relative_predefined_command_path(self, hunt_with_relative_executable_paths):
        compiled = compile_hunt(str(hunt_with_relative_executable_paths))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        exe = executables[0]
        assert exe.path == "hunts/scripts/check_user.py"
        assert "#!/usr/bin/env python3" in exe.content
        assert exe.permissions == 0o755

    def test_resolves_relative_supporting_files(self, hunt_with_relative_supporting_files):
        compiled = compile_hunt(str(hunt_with_relative_supporting_files))

        exe_paths = {a.path for a in _by_kind(compiled, "executable")}
        support_paths = {a.path for a in _by_kind(compiled, "support")}
        assert "hunts/scripts/check_ip.py" in exe_paths
        assert "hunts/scripts/ip_ranges.json" in support_paths

    def test_resolves_relative_inline_executable(self, hunt_with_relative_inline_executable):
        compiled = compile_hunt(str(hunt_with_relative_inline_executable))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        exe = executables[0]
        assert exe.path == "hunts/scripts/enrich.py"
        assert exe.permissions == 0o700

    def test_relative_paths_replaced_with_pkg_token(self, hunt_with_relative_executable_paths):
        """Stored YAML content should hold __pkg__/ tokens, never '..' fragments."""
        compiled = compile_hunt(str(hunt_with_relative_executable_paths))

        for yf in _by_kind(compiled, "yaml"):
            assert "../scripts/" not in yf.content

    def test_absolute_paths_still_work(self, hunt_with_executables):
        """Absolute path inputs compile to the same packaged rel as relative inputs."""
        compiled = compile_hunt(str(hunt_with_executables))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        assert executables[0].path == "hunts/scripts/check_user.py"


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

        compiled = compile_hunt(str(hunt_file))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 2
        exe_paths = {e.path for e in executables}
        assert "hunts/scripts/script_a.py" in exe_paths
        assert "hunts/scripts/script_b.py" in exe_paths


class TestCompileHuntWithBinaryExecutable:
    def test_binary_executable_uses_base64_encoding(self, hunt_with_binary_executable):
        hunt_file, original_bytes = hunt_with_binary_executable
        compiled = compile_hunt(str(hunt_file))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        exe = executables[0]
        assert exe.path == "hunts/scripts/lookup"
        assert exe.encoding == "base64"
        assert exe.permissions == 0o755
        assert base64.b64decode(exe.content) == original_bytes

    def test_text_executables_remain_text_encoding(self, hunt_with_inline_executable):
        compiled = compile_hunt(str(hunt_with_inline_executable))

        exe = _by_kind(compiled, "executable")[0]
        assert exe.encoding == "text"
        assert "#!/usr/bin/env python3" in exe.content


class TestCompileHuntCrossTreeReferences:
    """A monorepo hunt that reaches into sibling directories (hunts/splunk
    -> hunts/commands -> hunts/scripts) compiles without any '..' in
    packaged paths, because the package root covers every reference."""

    def test_packaged_paths_are_clean(self, hunt_with_cross_tree_references, hunt_dir):
        compiled = compile_hunt(str(hunt_with_cross_tree_references))

        assert compiled.package_root == str(hunt_dir)
        assert compiled.target == "hunts/splunk/azure_single_factor_authentication.yaml"

        for asset in compiled.assets:
            assert not asset.path.startswith(".."), asset.path
            assert "/../" not in asset.path, asset.path

    def test_executable_at_sibling_location(self, hunt_with_cross_tree_references):
        compiled = compile_hunt(str(hunt_with_cross_tree_references))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        assert executables[0].path == "hunts/scripts/is_service_account.py"

    def test_no_author_paths_in_compiled_artifact(
        self, hunt_with_cross_tree_references, hunt_dir
    ):
        """Regression guard: the author's absolute path must not appear in any
        asset content. This catches any reintroduction of string-based path
        rewriting that leaks the author's filesystem layout to the wire."""
        compiled = compile_hunt(str(hunt_with_cross_tree_references))

        for asset in compiled.assets:
            if asset.encoding == "text":
                assert str(hunt_dir) not in asset.content

    def test_pkg_token_appears_in_yaml_content(self, hunt_with_cross_tree_references):
        compiled = compile_hunt(str(hunt_with_cross_tree_references))

        commands_yaml = next(
            a for a in _by_kind(compiled, "yaml")
            if a.path == "hunts/commands/azure_commands.include.yaml"
        )
        assert PKG_TOKEN + "hunts/scripts/is_service_account.py" in commands_yaml.content


class TestCompileHuntOutOfPackageRoot:
    def test_executable_outside_package_root_raises(self, hunt_dir, tmp_path_factory):
        """A hunt that references a file outside package_root is rejected."""
        outside_dir = tmp_path_factory.mktemp("outside")
        external_script = outside_dir / "evil.py"
        external_script.write_text("#!/usr/bin/env python3\nprint('pwn')\n")
        external_script.chmod(0o755)

        hunt_file = hunt_dir / "hunts" / "test" / "escape.yaml"
        hunt_file.parent.mkdir(parents=True, exist_ok=True)
        hunt_file.write_text(
            "rule:\n"
            "  uuid: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\n"
            "  enabled: yes\n"
            "  name: escape_test\n"
            "  description: References a file outside the package root\n"
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
            f"            path: {external_script}\n"
        )

        with pytest.raises(OutOfPackageRootError) as exc_info:
            compile_hunt(str(hunt_file))

        assert str(external_script) in str(exc_info.value)
        assert str(hunt_dir) in str(exc_info.value)

    def test_hunt_file_itself_outside_raises(self, hunt_dir, tmp_path_factory):
        outside_dir = tmp_path_factory.mktemp("outside")
        outside_hunt = outside_dir / "stray.yaml"
        outside_hunt.write_text("rule:\n  name: stray\n")

        with pytest.raises(OutOfPackageRootError):
            compile_hunt(str(outside_hunt), package_root=str(hunt_dir))


class TestPackageRootDiscovery:
    def test_explicit_package_root_wins(self, hunt_dir, simple_hunt, tmp_path_factory):
        """An explicit package_root arg is used directly and does not trigger
        marker walk-up."""
        explicit_root = str(hunt_dir)
        compiled = compile_hunt(str(simple_hunt), package_root=explicit_root)
        assert compiled.package_root == explicit_root

    def test_marker_walk_up_finds_nearest_marker(self, tmp_path):
        """compile_hunt without package_root walks upward until it finds
        .hunt-root."""
        root = tmp_path / "myroot"
        root.mkdir()
        (root / ".hunt-root").write_text("")

        hunt_file = root / "nested" / "deep" / "foo.yaml"
        hunt_file.parent.mkdir(parents=True)
        hunt_file.write_text(
            "rule:\n"
            "  uuid: 11111111-0000-0000-0000-000000000000\n"
            "  name: marker_walkup\n"
            "  query: 'index=main'\n"
        )

        compiled = compile_hunt(str(hunt_file))
        assert compiled.package_root == str(root)
        assert compiled.target == "nested/deep/foo.yaml"

    def test_missing_marker_raises(self, tmp_path):
        """Without an explicit package_root and without a marker, the compiler
        raises PackageRootNotFound."""
        hunt_file = tmp_path / "orphan.yaml"
        hunt_file.write_text(
            "rule:\n  uuid: x\n  name: orphan\n  query: 'index=main'\n"
        )

        with pytest.raises(PackageRootNotFound):
            compile_hunt(str(hunt_file))

    def test_find_package_root_helper(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (root / ".hunt-root").write_text("")
        nested = root / "a" / "b" / "c.yaml"
        nested.parent.mkdir(parents=True)
        nested.write_text("")

        assert find_package_root(str(nested)) == str(root)

    def test_find_package_root_missing_marker(self, tmp_path):
        with pytest.raises(PackageRootNotFound):
            find_package_root(str(tmp_path / "unanchored.yaml"))


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
        compiled = compile_hunt(str(hunt_file))
        assert _by_kind(compiled, "query") == []
        assert _by_kind(compiled, "query_include") == []

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

        compiled = compile_hunt(str(file_a))
        assert len(_by_kind(compiled, "yaml")) == 2

    def test_json_roundtrip(self, simple_hunt):
        compiled = compile_hunt(str(simple_hunt))
        json_str = compiled.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)
        assert restored == compiled

    def test_assets_deduplicated_by_path(self, hunt_dir):
        """When multiple YAMLs reference the same script, it appears once."""
        scripts_dir = hunt_dir / "hunts" / "scripts"
        scripts_dir.mkdir(parents=True)
        script = scripts_dir / "shared.py"
        script.write_text("#!/usr/bin/env python3\nprint('shared')\n")
        script.chmod(0o755)

        commands_dir = hunt_dir / "hunts" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "a.include.yaml").write_text(
            "commands:\n"
            "  - name: shared\n"
            "    type: executable\n"
            "    path: ../scripts/shared.py\n"
        )
        (commands_dir / "b.include.yaml").write_text(
            "commands:\n"
            "  - name: shared_again\n"
            "    type: executable\n"
            "    path: ../scripts/shared.py\n"
        )

        hunt_file = hunt_dir / "hunts" / "test" / "dupes.yaml"
        hunt_file.parent.mkdir(parents=True, exist_ok=True)
        hunt_file.write_text(
            "include:\n"
            "  - ../commands/a.include.yaml\n"
            "  - ../commands/b.include.yaml\n"
            "rule:\n"
            "  uuid: dedup-test\n"
            "  name: dedup\n"
            "  query: 'index=main'\n"
        )

        compiled = compile_hunt(str(hunt_file))

        executables = _by_kind(compiled, "executable")
        assert len(executables) == 1
        assert executables[0].path == "hunts/scripts/shared.py"
