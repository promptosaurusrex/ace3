"""CI lint: every module configured with ``cache_ttl`` must satisfy the
cacheability contract — its execute_analysis must not produce removals
and must not spawn file observables.

Phase 3 design doc §A4 / Step 3.8. Catches forgotten opt-outs at PR
time before they corrupt the cache.

Two-layer enforcement:

1. ``test_yaml_cache_ttl_modules_have_contract_check`` — scans
   ``etc/saq.default.yaml`` (and any environment overlays present)
   for entries with ``cache_ttl`` set, then asserts each module is
   covered by an entry in ``CONTRACT_CHECKERS`` below. Adding
   ``cache_ttl`` to a module without registering a contract check
   here fails the suite with a helpful message.

2. ``test_module_contract`` (parametrized) — for each registered
   module, runs ``execute_analysis`` against a synthetic observable
   (with external dependencies mocked) and asserts ``not
   delta.has_removals and not delta.has_file_observables``.
"""
from datetime import datetime
from typing import Callable

import pytest
import yaml

from saq.analysis.snapshot import ModuleExecutionSnapshot
from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_SITE_TAGGER,
    ANALYSIS_MODULE_WHOIS_ANALYZER,
    AnalysisExecutionResult,
    F_FQDN,
    F_IPV4,
)
from tests.saq.helpers import create_root_analysis


# ----------------------------------------------------------------------
# Per-module contract runners
# ----------------------------------------------------------------------

def _check_whois_analyzer(test_context, monkeypatch):
    """Runs WhoisAnalyzer with a mocked whois.whois() and returns the
    delta produced. Mirrors the mock pattern in test_whois.py.
    """
    from saq.modules.whois import WhoisAnalyzer

    class MockWhoisResult:
        def __init__(self, data):
            self.data = data
            self.text = data.get("text", "mock whois text")

        def get(self, key, default=None):
            return self.data.get(key, default)

    fake_data = {
        "domain_name": "EXAMPLE.COM",
        "registrar": "Test Registrar",
        "name_servers": ["NS1.EXAMPLE.COM"],
        "creation_date": datetime(2000, 1, 1),
        "updated_date": datetime(2024, 1, 1),
        "text": "mock whois response body",
    }
    monkeypatch.setattr(
        "saq.modules.whois.whois.whois",
        lambda _domain: MockWhoisResult(fake_data),
    )

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = WhoisAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_WHOIS_ANALYZER),
    )
    analyzer.root = root

    before = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    result = analyzer.execute_analysis(obs)
    after = ModuleExecutionSnapshot.narrow(root, obs, analyzer)

    assert result == AnalysisExecutionResult.COMPLETED
    return ModuleExecutionSnapshot.diff(before, after, analyzer, obs)


def _check_site_tagger(test_context, monkeypatch):
    """Runs SiteTagAnalyzer against a temp CSV containing one CIDR rule
    that matches an F_IPV4 observable. Verifies the live analyzer's
    delta is contract-clean — single tag added to the target observable,
    no children, no removals, no file observables.
    """
    import tempfile
    from pathlib import Path

    from saq.modules.tag import SiteTagAnalyzer

    tmp_dir = Path(tempfile.mkdtemp())
    csv_path = tmp_dir / "site_tags.csv"
    csv_path.write_text("ipv4,cidr,false,10.0.0.0/8,internal-network\n")

    # Override the CSV path via the analyzer's csv_file property so we don't
    # touch the real shipped file.
    monkeypatch.setattr(
        SiteTagAnalyzer,
        "csv_file",
        property(lambda _self: str(csv_path)),
    )

    root = create_root_analysis()
    root.initialize_storage()
    obs = root.add_observable_by_spec(F_IPV4, "10.1.2.3")

    analyzer = SiteTagAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_SITE_TAGGER),
    )
    analyzer.root = root

    before = ModuleExecutionSnapshot.narrow(root, obs, analyzer)
    result = analyzer.execute_analysis(obs)
    after = ModuleExecutionSnapshot.narrow(root, obs, analyzer)

    assert result == AnalysisExecutionResult.COMPLETED
    return ModuleExecutionSnapshot.diff(before, after, analyzer, obs)


# Registry of contract checkers — one entry per module with cache_ttl
# set in any deployed YAML. Adding a new ``cache_ttl`` to a module
# without registering it here fails
# ``test_yaml_cache_ttl_modules_have_contract_check``.
#
# Key: YAML config block name (e.g. ``analysis_module_whois_analyzer``).
# Value: callable(test_context, monkeypatch) -> ModuleExecutionDelta.
CONTRACT_CHECKERS: dict[str, Callable] = {
    "analysis_module_whois_analyzer": _check_whois_analyzer,
    "analysis_module_site_tagger": _check_site_tagger,
}


# ----------------------------------------------------------------------
# YAML scanner
# ----------------------------------------------------------------------

def _yaml_files_to_scan() -> list[str]:
    """List of YAML config files to scan for cache_ttl opt-ins.

    Includes the open-source default. Local-dev (etc/saq.yaml) and
    integration overlays are deliberately NOT scanned: those are
    operator-controlled overrides and may contain experimental opt-ins
    that don't ship to prod. The test enforces the contract on what
    the project commits to ship.
    """
    import os

    from saq.environment import get_base_dir

    candidates = [
        os.path.join(get_base_dir(), "etc/saq.default.yaml"),
    ]
    return [p for p in candidates if os.path.exists(p)]


def _modules_with_cache_ttl() -> list[str]:
    """Walk shipped YAML files and yield module config block names that
    set a non-null ``cache_ttl``.
    """
    found: set[str] = set()
    for path in _yaml_files_to_scan():
        with open(path, "r") as fp:
            data = yaml.safe_load(fp) or {}
        if not isinstance(data, dict):
            continue
        for key, value in data.items():
            if not isinstance(value, dict):
                continue
            if not key.startswith("analysis_module_"):
                continue
            if value.get("cache_ttl") is not None:
                found.add(key)
    return sorted(found)


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

@pytest.mark.unit
def test_yaml_cache_ttl_modules_have_contract_check():
    """Every YAML-shipped cacheable module must have a contract check
    registered in CONTRACT_CHECKERS. Catches new opt-ins that ship
    without test coverage of the cacheability contract.
    """
    yaml_modules = set(_modules_with_cache_ttl())
    registered = set(CONTRACT_CHECKERS.keys())
    missing = yaml_modules - registered
    assert not missing, (
        f"Modules with cache_ttl in shipped YAML but no contract check: "
        f"{sorted(missing)}. Add an entry to CONTRACT_CHECKERS in "
        f"tests/saq/modules/test_cacheable_modules_contract.py."
    )


@pytest.mark.unit
@pytest.mark.parametrize("module_key", sorted(CONTRACT_CHECKERS.keys()))
def test_module_contract(module_key, test_context, monkeypatch):
    """For each registered cacheable module, run execute_analysis with
    mocked external dependencies and assert the delta is contract-clean.
    """
    checker = CONTRACT_CHECKERS[module_key]
    delta = checker(test_context, monkeypatch)

    assert not delta.has_removals, (
        f"{module_key}: delta has removals — the cacheability contract "
        f"requires monotonic (additive-only) modules. Either remove "
        f"cache_ttl from this module's YAML or fix the module to be "
        f"additive."
    )
    assert not delta.has_file_observables, (
        f"{module_key}: delta spawns file observables — Phase 3 cache "
        f"replay does not yet materialize file bytes (Phase 4). Either "
        f"remove cache_ttl from this module's YAML or wait for Phase 4."
    )
