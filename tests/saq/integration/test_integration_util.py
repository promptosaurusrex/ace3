import os
import pytest

from saq.integration.integration_util import (
    get_integration_var_base_dir,
    get_integration_name_from_path,
    get_integration_path_from_name
)


@pytest.fixture
def integration_base(tmpdir, monkeypatch):
    """Build a tmp ACE root with an empty `integrations/` subdir; patch get_base_dir to point at it.

    Returns the path to the `integrations` subdir so tests can populate it.
    """
    base = tmpdir.mkdir("ace_base")
    integrations_dir = base.mkdir("integrations")
    monkeypatch.setattr(
        "saq.integration.integration_util.get_base_dir",
        lambda: str(base),
    )
    return str(integrations_dir)


def _make_integration(parent_dir: str, name: str) -> str:
    """Create an integration directory with the required `integration.md` marker."""
    integration_dir = os.path.join(parent_dir, name)
    os.makedirs(integration_dir)
    with open(os.path.join(integration_dir, "integration.md"), "w") as f:
        f.write("# integration")
    return integration_dir


@pytest.mark.unit
class TestIntegrationUtil:

    def test_get_integration_var_base_dir(self):
        """Test that get_integration_var_base_dir returns correct path structure."""
        result = get_integration_var_base_dir()

        # Should end with 'var/integrations'
        assert result.endswith(os.path.join("var", "integrations"))

        # Should be an absolute path
        assert os.path.isabs(result)

    def test_get_integration_name_from_path_with_simple_path(self):
        """Test get_integration_name_from_path with simple directory name."""
        test_path = "/path/to/test_integration"
        result = get_integration_name_from_path(test_path)

        assert result == "test_integration"

    def test_get_integration_name_from_path_with_nested_path(self):
        """Test get_integration_name_from_path with nested directory structure."""
        test_path = "/very/deep/nested/path/my_integration"
        result = get_integration_name_from_path(test_path)

        assert result == "my_integration"

    def test_get_integration_name_from_path_with_trailing_slash(self):
        """Test get_integration_name_from_path with trailing slash."""
        test_path = "/path/to/integration_name/"
        with pytest.raises(ValueError):
            get_integration_name_from_path(test_path)

    def test_get_integration_name_from_path_with_relative_path(self):
        """Test get_integration_name_from_path with relative path."""
        test_path = "relative/path/integration"
        result = get_integration_name_from_path(test_path)

        assert result == "integration"

    def test_get_integration_name_from_path_with_single_directory(self):
        """Test get_integration_name_from_path with just a directory name."""
        test_path = "single_integration"
        result = get_integration_name_from_path(test_path)

        assert result == "single_integration"

    def test_get_integration_path_from_name(self, integration_base):
        """Test get_integration_path_from_name returns the directory of a valid integration."""
        expected = _make_integration(integration_base, "test_integration")

        result = get_integration_path_from_name("test_integration")

        assert result == expected
        assert os.path.isabs(result)

    def test_get_integration_path_from_name_with_special_characters(self, integration_base):
        """Test get_integration_path_from_name with names containing special characters."""
        test_cases = [
            "integration_with_underscores",
            "integration-with-dashes",
            "integration.with.dots",
            "integration123"
        ]

        expected_paths = {name: _make_integration(integration_base, name) for name in test_cases}

        for test_name, expected in expected_paths.items():
            result = get_integration_path_from_name(test_name)
            assert result == expected
            assert os.path.isabs(result)

    def test_integration_functions_consistency(self, integration_base):
        """Test that get_integration_name_from_path and get_integration_path_from_name round-trip."""
        test_name = "consistent_test"
        expected_path = _make_integration(integration_base, test_name)

        path_from_name = get_integration_path_from_name(test_name)
        name_from_path = get_integration_name_from_path(path_from_name)

        assert path_from_name == expected_path
        assert name_from_path == test_name

    def test_path_handling_edge_cases(self):
        """Test edge cases for path handling."""
        # Empty string should raise ValueError
        with pytest.raises(ValueError):
            get_integration_name_from_path("")

        # Root path
        with pytest.raises(ValueError):
            get_integration_name_from_path("/")

        # Path with only slashes
        with pytest.raises(ValueError):
            get_integration_name_from_path("//")

    @pytest.mark.parametrize(
        "test_path,expected",
        [
            ("/path/to/my_integration", "my_integration"),
            ("/path/to/my_integration/", pytest.raises(ValueError)),
            ("/path/to//my_integration", "my_integration"),
            ("/path/to/../to/my_integration", "my_integration"),
        ]
    )
    def test_path_normalization(self, test_path, expected):
        """Test that paths are handled correctly regardless of format."""
        if isinstance(expected, str):
            assert get_integration_name_from_path(test_path) == expected
        else:
            with expected:
                get_integration_name_from_path(test_path)


@pytest.mark.unit
class TestGetIntegrationPathFromNameDiscovery:
    """Tests for the recursive discovery behavior of get_integration_path_from_name."""

    def test_nested_discovery(self, integration_base):
        """Integrations nested under intermediate directories are discovered by basename."""
        parent_dir = os.path.join(integration_base, "parent", "integrations")
        os.makedirs(parent_dir)
        expected = _make_integration(parent_dir, "child")

        assert get_integration_path_from_name("child") == expected

    def test_top_level_discovery(self, integration_base):
        """Integrations directly under the base dir are still discovered (flat layout)."""
        expected = _make_integration(integration_base, "flat")

        assert get_integration_path_from_name("flat") == expected

    def test_missing_raises_filenotfound(self, integration_base):
        """A name with no matching integration directory raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            get_integration_path_from_name("nonexistent")

    def test_collision_raises_valueerror(self, integration_base):
        """Two integrations sharing a basename raise ValueError listing both paths."""
        first_parent = os.path.join(integration_base, "a")
        second_parent = os.path.join(integration_base, "b")
        os.makedirs(first_parent)
        os.makedirs(second_parent)
        first = _make_integration(first_parent, "dup")
        second = _make_integration(second_parent, "dup")

        with pytest.raises(ValueError) as exc_info:
            get_integration_path_from_name("dup")

        assert first in str(exc_info.value)
        assert second in str(exc_info.value)

    def test_ignores_dirs_without_integration_md(self, integration_base):
        """Directories without the integration.md marker are not considered integrations."""
        orphan_dir = os.path.join(integration_base, "orphan")
        os.makedirs(orphan_dir)

        with pytest.raises(FileNotFoundError):
            get_integration_path_from_name("orphan")
