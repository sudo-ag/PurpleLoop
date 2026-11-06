"""Red earned-mode doctrine: ProFTPD mod_copy RCE via real msfconsole.

No-seeding rule: the doctrine may supply tradecraft (which msf module exists,
how to drive it) but must NEVER assert that the target runs ProFTPD or that the
service is vulnerable — that stays red's own fingerprint-first discovery.
"""
from src.agents import RedAgent
from src.mock_executor import MockExecutor


def _earned_prompt() -> str:
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=True)
    return red.system_prompt


def test_earned_prompt_is_fingerprint_first_for_ftp():
    prompt = _earned_prompt()
    # Red must fingerprint the banner ITSELF — a service/version is a fact about
    # the box, discovered, not asserted.
    assert "nmap -sV" in prompt
    # The discovery boundary is stated explicitly (no-seeding): the module
    # catalog is tradecraft, but which service/module applies is red's call.
    assert "stays your discovery" in prompt


def test_earned_prompt_module_invocation_is_gated_on_proftpd_and_held_cred():
    prompt = _earned_prompt()
    assert "exploit/unix/ftp/proftpd_modcopy_exec" in prompt
    # The attempt is conditional on the banner identifying ProFTPD AND red
    # already holding a cracked cred — never an unconditional "it is ProFTPD".
    assert "only if" in prompt.lower()
    assert "ProFTPD" in prompt
    # Precondition references the REAL held-credential mechanism (the cred red
    # passed to use_credential), not an invented one.
    assert "use_credential" in prompt
    assert "FTPUSER" in prompt and "FTPPASS" in prompt


def test_earned_prompt_requires_honest_rce_verification():
    prompt = _earned_prompt()
    # "exploit completed" is not proof: red must request the planted page and
    # confirm real command output comes back.
    assert "curl" in prompt
    assert "uid=" in prompt
    assert "cmd=id" in prompt


def test_non_earned_redagent_has_no_proftpd_doctrine():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=False)
    prompt = red.system_prompt
    assert "proftpd_modcopy_exec" not in prompt
    assert "nmap -sV" not in prompt
