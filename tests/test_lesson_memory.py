"""knowledge.json hygiene: dedupe near-duplicate lessons and cap the list."""
from src.orchestrator import merge_lesson, dedupe_lessons, _LESSON_CAP


def test_novel_lesson_is_appended():
    assert merge_lesson(["a port scan got me contained"], "the flag lived in /root") == [
        "a port scan got me contained", "the flag lived in /root"]


def test_exact_duplicate_is_skipped():
    lessons = ["blocking the attacker IP ends the recon fast"]
    assert merge_lesson(lessons, "blocking the attacker IP ends the recon fast") == lessons


def test_bullet_and_case_only_difference_is_a_duplicate():
    lessons = ["Blocking the attacker IP ends the recon fast"]
    assert merge_lesson(lessons, "* blocking the ATTACKER ip ends the recon fast") == lessons


def test_near_duplicate_wording_is_skipped():
    # The real failure mode: two reworded "whoami at turn 1 got detected" lessons.
    lessons = ["Executing the 'whoami' command at turn 1 led to detection by Blue, so next time avoid it"]
    near = "Using the 'whoami' command at turn 1 led to being detected by blue, so next time avoid it"
    assert merge_lesson(lessons, near) == lessons


def test_reordered_clauses_caught_by_token_overlap():
    # Same lesson, clauses reordered — char-sequence similarity misses it, token
    # Jaccard catches it.
    lessons = ["block the suspicious ip first, then keep investigating the auth logs"]
    reordered = "keep investigating the auth logs, then block the suspicious ip first"
    assert merge_lesson(lessons, reordered) == lessons


def test_empty_lesson_is_ignored():
    assert merge_lesson(["x"], "") == ["x"]
    assert merge_lesson(["x"], None) == ["x"]


def test_cap_keeps_most_recent():
    lessons = [f"distinct lesson number {i} about a unique tactic" for i in range(_LESSON_CAP)]
    out = merge_lesson(lessons, "a brand new distinct lesson about kernel exploits")
    assert len(out) == _LESSON_CAP
    assert out[-1] == "a brand new distinct lesson about kernel exploits"
    assert lessons[0] not in out  # oldest dropped


def test_dedupe_collapses_an_accumulated_bloated_list():
    bloat = [
        "* repeating failed find and sudo commands led to a stalemate, pivot to kernel exploits",
        "• Repeating failed `find` and sudo commands led to a stalemate, so pivot to kernel exploits",
        "repeating the same failed find and sudo commands led to a stalemate, pivot to kernel exploits next",
        "a loud nmap scan got my IP contained, go quieter next time",
    ]
    out = dedupe_lessons(bloat)
    assert len(out) == 2  # three near-dupes collapse to one, plus the nmap lesson
