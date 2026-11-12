"""Optional --narrate LLM polish pass; default OFF."""
import inspect
from unittest.mock import MagicMock

from src.debrief import make_polish
from src.arena import run_episodes


def test_make_polish_sends_skeleton_and_returns_model_text():
    client = MagicMock()
    client.chat.return_value = {"message": {"content": "polished prose"}}
    polish = make_polish(client, "some-model")
    assert polish("SKELETON", "red") == "polished prose"
    assert client.chat.called


def test_narrate_defaults_off():
    assert inspect.signature(run_episodes).parameters["narrate"].default is False
