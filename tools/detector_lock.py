"""Write or check the detector lock file (tests/detectors.lock.json).

    python tools/detector_lock.py --check    # exit 1 if the patterns differ from the lock
    python tools/detector_lock.py --write    # record the current patterns

The lock stores a digest of every detector's regular expression plus the set
fingerprint. Changing a pattern, severity or category, or adding or removing a
detector, changes the fingerprint; the governance tests then fail until the lock
is rewritten AND the new fingerprint is recorded in CHANGELOG.md, so that a
detection change is never silent.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
from ramnesia.patterns import ALL_DETECTORS, detector_fingerprint, pattern_digest  # noqa: E402

LOCK = os.path.join(ROOT, "tests", "detectors.lock.json")


def current():
    return {"fingerprint": detector_fingerprint(),
            "detectors": {d.name: {"category": d.category, "severity": d.severity, "pattern_sha256": pattern_digest(d)} for d in ALL_DETECTORS}}


def main(argv):
    if "--write" in argv:
        with open(LOCK, "w", encoding="utf-8") as fh:
            json.dump(current(), fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {LOCK}: fingerprint {current()['fingerprint']}. Record it in CHANGELOG.md.")
        return 0
    with open(LOCK, encoding="utf-8") as fh:
        locked = json.load(fh)
    now = current()
    if locked == now:
        print(f"lock matches: {now['fingerprint']}")
        return 0
    for name in sorted(set(locked["detectors"]) | set(now["detectors"])):
        a, b = locked["detectors"].get(name), now["detectors"].get(name)
        if a != b:
            print("changed:" if a and b else "added:" if b else "removed:", name)
    print(f"locked {locked['fingerprint']} != current {now['fingerprint']}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
