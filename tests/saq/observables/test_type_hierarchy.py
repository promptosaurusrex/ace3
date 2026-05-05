import pytest

from saq.observables.type_hierarchy import (
    ObservableTypeEntry,
    ObservableTypesFile,
    TypeHierarchy,
    get_type_hierarchy,
)


@pytest.mark.unit
def test_singleton_returns_same_instance():
    assert get_type_hierarchy() is get_type_hierarchy()


@pytest.mark.unit
def test_unknown_type_has_no_parent_or_ancestors():
    h = TypeHierarchy()
    assert h.parent_of("nope") is None
    assert h.ancestors("nope") == ()


@pytest.mark.unit
def test_is_subtype_of_self():
    h = TypeHierarchy()
    assert h.is_subtype("anything", "anything") is True


@pytest.mark.unit
def test_yaml_load_and_subtype():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
          pdf_file: { extends: file }
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.parent_of("return_path") == "email_address"
    assert h.parent_of("pdf_file") == "file"
    assert h.is_subtype("return_path", "email_address") is True
    assert h.is_subtype("pdf_file", "file") is True


@pytest.mark.unit
def test_yaml_loads_inheritance_chain():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          priority_return_path: { extends: return_path }
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.ancestors("priority_return_path") == ("return_path", "email_address")
    assert h.is_subtype("priority_return_path", "email_address") is True
    assert h.is_subtype("priority_return_path", "return_path") is True


@pytest.mark.unit
def test_yaml_cycle_is_rejected_state_preserved(caplog):
    h = TypeHierarchy()
    good_yaml = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(good_yaml)
    assert h.parent_of("return_path") == "email_address"

    bad_yaml = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
          email_address: { extends: return_path }
        """
    )
    with caplog.at_level("ERROR"):
        h.load_yaml_config(bad_yaml)

    # Prior YAML state intact, bad YAML not applied.
    assert h.parent_of("return_path") == "email_address"
    assert h.parent_of("email_address") is None
    assert any("cycle" in r.message.lower() for r in caplog.records)


@pytest.mark.unit
def test_yaml_missing_file_logs_and_no_state_change(caplog):
    h = TypeHierarchy()
    good_yaml = _write_yaml(
        """
        types:
          return_path: { extends: email_address }
        """
    )
    h.load_yaml_config(good_yaml)
    with caplog.at_level("ERROR"):
        h.load_yaml_config("/nonexistent/path/to/inheritance.yaml")

    assert h.parent_of("return_path") == "email_address"


@pytest.mark.unit
def test_yaml_schema_rejects_unknown_keys(caplog):
    h = TypeHierarchy()
    bad = _write_yaml(
        """
        types:
          return_path:
            extends: email_address
            color: red
        """
    )
    with caplog.at_level("ERROR"):
        h.load_yaml_config(bad)
    assert h.parent_of("return_path") is None


@pytest.mark.unit
def test_typed_config_model_validates():
    cfg = ObservableTypesFile.model_validate(
        {"types": {"a": {"extends": "b"}}}
    )
    assert cfg.types["a"].extends == "b"
    assert cfg.types["a"].default_display_type is None


@pytest.mark.unit
def test_observable_type_entry_all_fields_optional():
    # All fields optional — an entry can be empty.
    entry = ObservableTypeEntry()
    assert entry.extends is None
    assert entry.default_display_type is None
    assert entry.description is None
    assert entry.deprecated is False


@pytest.mark.unit
def test_default_display_type_unset_returns_none():
    h = TypeHierarchy()
    assert h.default_display_type_for("anything") is None


@pytest.mark.unit
def test_yaml_loads_default_display_type():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          return_path:
            extends: email_address
            default_display_type: "Mail Return Path"
          azure_user_id:
            default_display_type: "Azure User ID"
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.default_display_type_for("return_path") == "Mail Return Path"
    assert h.default_display_type_for("azure_user_id") == "Azure User ID"
    # azure_user_id has no extends, so it has no parent
    assert h.parent_of("azure_user_id") is None


@pytest.mark.unit
def test_yaml_entry_with_only_default_display_type_loads():
    """An entry can carry just default_display_type and no extends."""
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          azure_user_id:
            default_display_type: "Azure User ID"
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.default_display_type_for("azure_user_id") == "Azure User ID"
    assert h.parent_of("azure_user_id") is None


@pytest.mark.unit
def test_yaml_reload_clears_removed_default_display_type():
    h = TypeHierarchy()
    first = _write_yaml(
        """
        types:
          azure_user_id:
            default_display_type: "Azure User ID"
        """
    )
    h.load_yaml_config(first)
    assert h.default_display_type_for("azure_user_id") == "Azure User ID"

    second = _write_yaml(
        """
        types:
          azure_user_id:
            extends: user
        """
    )
    h.load_yaml_config(second)
    assert h.default_display_type_for("azure_user_id") is None
    assert h.parent_of("azure_user_id") == "user"


@pytest.mark.unit
def test_description_unset_returns_none():
    h = TypeHierarchy()
    assert h.description_for("anything") is None


@pytest.mark.unit
def test_yaml_loads_description():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          email_address:
            description: "email address"
          azure_user_id:
            description: "Azure user identifier"
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.description_for("email_address") == "email address"
    assert h.description_for("azure_user_id") == "Azure user identifier"
    assert h.description_for("nope") is None


@pytest.mark.unit
def test_is_deprecated_default_false():
    h = TypeHierarchy()
    assert h.is_deprecated("anything") is False


@pytest.mark.unit
def test_yaml_loads_deprecated_flag():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          email_address:
            description: "email address"
          pcap:
            description: "deprecated"
            deprecated: true
        """
    )
    h.load_yaml_config(yaml_path)

    assert h.is_deprecated("pcap") is True
    assert h.is_deprecated("email_address") is False


@pytest.mark.unit
def test_yaml_declared_types_includes_empty_entries():
    h = TypeHierarchy()
    yaml_path = _write_yaml(
        """
        types:
          empty_entry: {}
          described:
            description: "has a description"
          extends_one:
            extends: described
        """
    )
    h.load_yaml_config(yaml_path)

    declared = h.yaml_declared_types()
    assert declared == {"empty_entry", "described", "extends_one"}


@pytest.mark.unit
def test_yaml_reload_clears_removed_description_and_deprecated():
    h = TypeHierarchy()
    first = _write_yaml(
        """
        types:
          pcap:
            description: "old packet capture"
            deprecated: true
        """
    )
    h.load_yaml_config(first)
    assert h.description_for("pcap") == "old packet capture"
    assert h.is_deprecated("pcap") is True

    second = _write_yaml(
        """
        types:
          email_address:
            description: "email address"
        """
    )
    h.load_yaml_config(second)
    assert h.description_for("pcap") is None
    assert h.is_deprecated("pcap") is False


@pytest.mark.unit
def test_get_all_valid_types_combines_yaml_and_python():
    """A type counts as valid whether it has a Python class or only a YAML entry."""
    from saq.observables.generator import OBSERVABLE_TYPE_MAPPING
    from saq.observables.type_hierarchy import get_all_valid_types

    h = get_type_hierarchy()
    declared_snapshot = set(h._yaml_declared_types)
    h._yaml_declared_types.add("__pytest_yaml_only__")
    try:
        result = set(get_all_valid_types())
        assert "__pytest_yaml_only__" in result
        # A python-registered type that's not in YAML still appears.
        assert "test" in result  # F_TEST has a registered TestObservable class
        # Sanity: the result spans both sources
        assert set(OBSERVABLE_TYPE_MAPPING.keys()).issubset(result)
    finally:
        h._yaml_declared_types = declared_snapshot


def _write_yaml(content: str) -> str:
    import os
    import tempfile
    import textwrap

    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(textwrap.dedent(content))
    return path
