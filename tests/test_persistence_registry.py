"""Plant registry on SimulationState: records every verified plant and its
eviction so a persistence pursuit can ask 'what still stands?' at any moment."""
from src.orchestrator import SimulationState


def test_record_plant_appends_standing():
    s = SimulationState()
    s.record_plant(["task|\\A", "startup|C:\\x\\y.lnk"], turn=2)
    standing = s.standing_plants()
    ids = {p["identity"] for p in standing}
    assert ids == {"task|\\A", "startup|C:\\x\\y.lnk"}
    assert all(p["planted_turn"] == 2 and p["evicted_turn"] is None for p in standing)


def test_record_plant_dedupes_standing():
    s = SimulationState()
    s.record_plant(["task|\\A"], turn=2)
    s.record_plant(["task|\\A"], turn=4)  # already standing — not a new record
    assert len(s.standing_plants()) == 1


def test_mark_evicted_sets_turn_on_matching():
    s = SimulationState()
    s.record_plant(["task|\\A", "task|\\B"], turn=2)
    s.mark_evicted(["task|\\A"], turn=5)
    standing = s.standing_plants()
    assert [p["identity"] for p in standing] == ["task|\\B"]
    a = next(p for p in s.persistence_plants if p["identity"] == "task|\\A")
    assert a["evicted_turn"] == 5


def test_replant_after_eviction_is_new_record():
    s = SimulationState()
    s.record_plant(["task|\\A"], turn=2)
    s.mark_evicted(["task|\\A"], turn=3)
    s.record_plant(["task|\\A"], turn=4)  # reappeared after eviction — a new round
    records = [p for p in s.persistence_plants if p["identity"] == "task|\\A"]
    assert len(records) == 2
    assert len(s.standing_plants()) == 1
