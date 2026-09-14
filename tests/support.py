from pathlib import Path

from honeypot.parser.log_parser import JsonlHoneypotParser

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name: str):
    """Load a TEST FIXTURE JSONL file. These records are not production data."""
    events, failures = JsonlHoneypotParser().parse_file(FIXTURES_DIR / name)
    return events, failures
