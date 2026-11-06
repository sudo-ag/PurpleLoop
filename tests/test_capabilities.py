from src.agents import RED_EARNED_ADDENDUM
from src.capabilities import CAPABILITY_CATALOG, ServiceCapability


def test_catalog_has_exactly_one_entry():
    assert len(CAPABILITY_CATALOG) == 1
    assert isinstance(CAPABILITY_CATALOG[0], ServiceCapability)


def test_proftpd_module_string_is_exact():
    assert CAPABILITY_CATALOG[0].msf_module == "exploit/unix/ftp/proftpd_modcopy_exec"


def test_catalog_module_does_not_drift_from_doctrine():
    # If the hand-written doctrine and this data module ever disagree on the
    # module path, this fails — the catalog is a back-fill of the live prose.
    assert CAPABILITY_CATALOG[0].msf_module in RED_EARNED_ADDENDUM
