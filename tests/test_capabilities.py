import pytest

from src.agents import RED_EARNED_ADDENDUM
from src.capabilities import CAPABILITY_CATALOG, ServiceCapability


def test_catalog_has_exactly_two_entries():
    assert len(CAPABILITY_CATALOG) == 2
    assert all(isinstance(entry, ServiceCapability) for entry in CAPABILITY_CATALOG)


def test_proftpd_module_string_is_exact():
    assert CAPABILITY_CATALOG[0].msf_module == "exploit/unix/ftp/proftpd_modcopy_exec"


def test_drupal_module_string_is_exact():
    assert (
        CAPABILITY_CATALOG[1].msf_module == "exploit/multi/http/drupal_drupageddon"
    )


@pytest.mark.parametrize("entry", CAPABILITY_CATALOG, ids=lambda e: e.service_pattern)
def test_catalog_module_does_not_drift_from_doctrine(entry: ServiceCapability):
    # If the hand-written doctrine and this data module ever disagree on the
    # module path, this fails — the catalog is a back-fill of the live prose.
    assert entry.msf_module in RED_EARNED_ADDENDUM
