"""Task 3: scripted_reset re-vulnerabilises paths blue hardened, so the box
returns to its attackable baseline each episode and the dojo never runs dry."""
from types import SimpleNamespace
from unittest.mock import MagicMock
from src.arena import scripted_reset


def _blue_ex(hardenings):
    ex = MagicMock()
    ex.execute = MagicMock(return_value="")
    ex.hardenings = list(hardenings)
    return ex


def _red():
    return SimpleNamespace(jump_host=None)


def test_reset_restores_recorded_modes():
    blue = _blue_ex([{"path": "/opt/sinatra", "original_mode": "775",
                      "original_owner": "lando_calrissian", "original_group": "devs"}])
    scripted_reset(blue, _red(), episode=1)
    issued = " ".join(c.args[0] for c in blue.execute.call_args_list)
    # owner AND group must be restored, or a group-writable vector stays closed.
    assert "chown lando_calrissian:devs /opt/sinatra" in issued
    assert "chmod 775 /opt/sinatra" in issued
    assert blue.hardenings == []


def test_reset_with_no_hardenings_is_noop():
    blue = _blue_ex([])
    scripted_reset(blue, _red(), episode=1)
    issued = " ".join(c.args[0] for c in blue.execute.call_args_list)
    assert "chmod" not in issued or "/opt/" not in issued
    assert blue.hardenings == []
