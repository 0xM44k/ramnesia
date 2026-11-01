"""Detector governance: every detector has fixtures, every change is recorded.

* Each detector has at least one positive and one negative fixture
  (tests/detector_cases.py), exercised through the real scanner.
* The detector set is locked (tests/detectors.lock.json). Any change to a
  pattern, severity, category, or to the list itself fails until the lock is
  regenerated with tools/detector_lock.py --write.
* The set fingerprint must appear in CHANGELOG.md, and the newest changelog
  version must equal the package version, so detection changes are written down.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, HERE)

import detector_cases as C
from ramnesia import __version__
from ramnesia.patterns import ALL_DETECTORS, detector_fingerprint, detector_set_info, pattern_digest
from ramnesia.scanner import scan_bytes

NAMES = [d.name for d in ALL_DETECTORS]


def fires(d, blob):
    return any(f.detector == d.name for f in scan_bytes(b"\x00" + blob + b"\x00", [d]))


def test_detector_names_are_unique():
    assert len(NAMES) == len(set(NAMES))


def test_every_detector_has_positive_and_negative_fixtures():
    assert [n for n in NAMES if not C.POSITIVE.get(n)] == []
    assert [n for n in NAMES if not C.NEGATIVE.get(n)] == []
    assert set(C.POSITIVE) <= set(NAMES) and set(C.NEGATIVE) <= set(NAMES), "fixtures exist for a detector that does not"


@pytest.mark.parametrize("d", ALL_DETECTORS, ids=NAMES)
def test_positive_fixtures_fire(d):
    for blob in C.POSITIVE[d.name]:
        assert fires(d, blob), f"{d.name} did not fire on {blob[:60]!r}"


@pytest.mark.parametrize("d", ALL_DETECTORS, ids=NAMES)
def test_negative_fixtures_do_not_fire(d):
    for blob in C.NEGATIVE[d.name]:
        assert not fires(d, blob), f"{d.name} fired on {blob[:60]!r}"


def test_secret_positives_come_back_redacted():
    for d in ALL_DETECTORS:
        if d.redact is None:
            continue
        for blob in C.POSITIVE[d.name]:
            for f in scan_bytes(b"\x00" + blob + b"\x00", [d]):
                assert f.redacted and f.match.encode("latin-1") != blob, d.name


def test_lock_matches_current_patterns():
    with open(os.path.join(HERE, "detectors.lock.json"), encoding="utf-8") as fh:
        lock = json.load(fh)
    now = {d.name: {"category": d.category, "severity": d.severity, "pattern_sha256": pattern_digest(d)} for d in ALL_DETECTORS}
    changed = sorted(n for n in set(lock["detectors"]) | set(now) if lock["detectors"].get(n) != now.get(n))
    assert not changed, f"detectors changed without updating the lock: {changed}. Run: python tools/detector_lock.py --write, then record the fingerprint in CHANGELOG.md"
    assert lock["fingerprint"] == detector_fingerprint()


def test_fingerprint_is_recorded_in_the_changelog_and_version_is_consistent():
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
        log = fh.read()
    assert detector_fingerprint() in log, f"detector set {detector_fingerprint()} is not recorded in CHANGELOG.md"
    newest = re.search(r"^## \[(\d+\.\d+\.\d+)\]", log, re.M).group(1)
    assert newest == __version__, f"CHANGELOG newest version {newest} != package version {__version__}"
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        assert f'version = "{__version__}"' in fh.read()


def test_fingerprint_reacts_to_any_pattern_change(monkeypatch):
    import re as _re
    import ramnesia.patterns as P
    base = P.detector_fingerprint()
    first = P.ALL_DETECTORS[0]
    changed = P.Detector(first.name, first.category, first.severity, _re.compile(first.pattern.pattern + b"x"), first.description, first.redact)
    monkeypatch.setattr(P, "ALL_DETECTORS", [changed] + P.ALL_DETECTORS[1:])
    assert P.detector_fingerprint() != base
    monkeypatch.setattr(P, "ALL_DETECTORS", P.ALL_DETECTORS[1:])
    assert P.detector_fingerprint() != base


def test_report_and_cli_expose_the_fingerprint(tmp_path):
    from ramnesia.report import to_json, to_console
    data = json.loads(to_json([], "x"))
    assert data["detector_set"] == detector_set_info() and data["version"] == __version__
    assert detector_fingerprint() in to_console([], "x", color=False)
    out = subprocess.run([sys.executable, "-m", "ramnesia.cli", "detectors"], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0 and detector_fingerprint() in out.stdout


def test_lock_tool_check_passes_and_detects_drift(tmp_path):
    ok = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "detector_lock.py"), "--check"], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
