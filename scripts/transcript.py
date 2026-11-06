"""Transcript scrub: mask secrets left in Claude Code's session transcript, in place.

The transcript keeps every hook's stdout as written. A PostToolUse hook that replaces a
tool's output carries the raw output in its own stdout, so a secret redacted before the
model saw it can still land on disk there, or in a file Read and a pasted prompt.
scrub() reads the rows written since its last run and overwrites each secret it finds
with '*' of the same byte length: the file never moves, shrinks or loses a row.
"""
import json
import os

import leaks

MASK = b"*"


def offset(state):
    """Bytes of the transcript already scrubbed, as the state file records them."""
    try:
        with open(state, encoding="utf-8") as f:
            return int(f.read())
    except (OSError, ValueError):
        return 0


def pending(path, state):
    """The transcript changed size since the last run: there are rows to read."""
    return os.path.getsize(path) != offset(state)


def _strings(value, depth=1):
    """(text, depth) for every string in a JSON value, opening strings that hold JSON (a hook's stdout)."""
    if isinstance(value, str):
        if value.lstrip()[:1] in ("{", "["):
            try:
                inner = json.loads(value)
            except ValueError:
                inner = None
            if isinstance(inner, (dict, list)):
                yield from _strings(inner, depth + 1)
                return
        yield value, depth
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, depth)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item, depth)


def secrets(text, known, patterns):
    """(kind, value) for each secret in text, by the rules leaks.redact applies."""
    found = [("known-secret", v) for v in known if v in text]
    for kind, rx in patterns:
        for m in rx.finditer(text):
            if "v" not in rx.groupindex:
                found.append((kind, m.group(0)))
            elif not (kind in leaks.GENERIC and leaks.PLACEHOLDER.search(m.group("v"))):
                found.append((kind, m.group("v")))
    found += [("fi-personal-id", m.group(0)) for m in leaks.HETU.finditer(text) if leaks._hetu_valid(m)]
    return found


def _forms(value, depth):
    """The value as it sits in the raw line: JSON-escaped once per level of nesting."""
    forms = set()
    for _ in range(depth):
        value = json.dumps(value, ensure_ascii=False)[1:-1]
        try:
            forms.add(value.encode("utf-8"))
        except UnicodeEncodeError:
            pass   # a lone surrogate: the writer escaped it some other way
    return forms


def _after_backslash(raw, at):
    """raw[at] is the second character of an escape such as \\n, so masking from there would break the JSON."""
    run = 0
    while at - run > 0 and raw[at - run - 1] == 0x5C:
        run += 1
    return run % 2 == 1


def mask_line(raw, known, patterns):
    """(masked line, kinds) for one transcript row; the line comes back as is when nothing is found."""
    try:
        row = json.loads(raw)
    except ValueError:
        return raw, []
    kinds, values, depth = [], set(), 1
    for text, level in _strings(row):
        depth = max(depth, level)
        for kind, value in secrets(text, known, patterns):
            kinds.append(kind)
            values.add(value)
    masked = bytearray(raw)
    for value in values:
        for needle in _forms(value, depth):
            at = raw.find(needle)
            while at >= 0:
                if not _after_backslash(raw, at):
                    masked[at:at + len(needle)] = MASK * len(needle)
                at = raw.find(needle, at + 1)
    return bytes(masked), kinds


def scrub(path, state, known, patterns, mask=True):
    """Scrub the rows written since the last run; counts for the log, or None when there was nothing new.

    Only complete lines are read: a row still being written waits for the next run. A masked
    row is written back only when it still parses as JSON. With mask off the file is opened
    read-only and the counts say what masking would have done.
    """
    start, size = offset(state), os.path.getsize(path)
    if start > size:
        start = 0   # rewritten or replaced since the last run
    kinds, rows, skipped = [], 0, 0
    with open(path, "r+b" if mask else "rb") as f:
        f.seek(start)
        data = f.read(size - start)
        end = data.rfind(b"\n") + 1
        pos = 0
        while pos < end:
            stop = data.index(b"\n", pos) + 1
            line = data[pos:stop]
            masked, found = mask_line(line, known, patterns)
            kinds += found
            if masked != line:
                try:
                    json.loads(masked)
                except ValueError:
                    skipped += 1
                else:
                    rows += 1
                    if mask:
                        f.seek(start + pos)
                        f.write(masked)
            pos = stop
    os.makedirs(os.path.dirname(os.path.abspath(state)), exist_ok=True)
    with open(state, "w", encoding="utf-8") as f:
        f.write(str(start + end))
    if not kinds:
        return None
    return {"found": sorted(set(kinds)), "values": len(kinds), "rows": rows, "skipped": skipped, "masked": mask}
