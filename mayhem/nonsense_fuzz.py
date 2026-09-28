#!/usr/bin/env python3
"""Atheris fuzz harness for nostril's nonsense() detector.

Ported from the original OSS-Fuzz-style harness (archive/original-master
mayhem/nonsense_fuzz.py): feed arbitrary unicode strings to nonsense(),
which raises ValueError on inputs it deems non-testable (too short,
non-alphabetic, ...) — that is expected API behavior, not a bug.

This is the buggy-mhh-run-4 backport: at this commit, string_score() looks
up character n-grams in a defaultdict(NGramData) whose default factory
can't be called with zero args, so any input containing an untrained
n-gram raises TypeError (nostril/nonsense_detector.py, Mayhem defect
3229461, CWE-704) — the bug this branch reproduces, so it is left to
crash rather than caught (unlike the live target's harness, which treats
it as a known finding to keep fuzzing productive).
"""
import sys

import atheris

with atheris.instrument_imports():
    from nostril import nonsense


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    n_str = fdp.ConsumeUnicodeNoSurrogates(64)
    try:
        nonsense(n_str)
    except ValueError:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
