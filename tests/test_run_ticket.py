"""lab/run_ticket.py 순수 함수 시험(구현계획 Task 7의 리뷰 중점 1·2)."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("run_ticket", ROOT / "lab" / "run_ticket.py")
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)

NOW = datetime(2026, 11, 11, 9, 0, tzinfo=timezone.utc)


def test_window_blocks_rerun_within_15min():
    assert rt.window_blocked(NOW - timedelta(minutes=10), NOW, 15) == 300


def test_window_allows_after():
    assert rt.window_blocked(NOW - timedelta(minutes=16), NOW, 15) is None


def test_window_allows_first_run():
    assert rt.window_blocked(None, NOW, 30) is None


def test_precheck_flags_leftover():
    assert rt.precheck(["203.0.113.22"], [], "203.0.113.22") == ["portal_block_left:203.0.113.22"]


def test_precheck_flags_pf_leftover():
    assert rt.precheck([], ["203.0.113.22"], "203.0.113.22") == ["pf_block_left:203.0.113.22"]


def test_precheck_ignores_other_sources():
    assert rt.precheck(["203.0.113.11"], [], "203.0.113.22") == []


def test_mttd_seconds():
    start = NOW
    assert rt.mttd(start, start + timedelta(seconds=49, milliseconds=281)) == 49.281


def test_ticket_profiles_match_team_sources_and_windows():
    assert rt.TICKETS["S1"]["src"] == "203.0.113.11" and rt.TICKETS["S1"]["window_min"] == 30
    assert rt.TICKETS["S8"]["src"] == "203.0.113.21" and rt.TICKETS["S8"]["window_min"] == 15
    assert rt.TICKETS["S10"]["src"] == "203.0.113.22" and rt.TICKETS["S10"]["window_min"] == 15
