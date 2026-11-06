"""Statistics on the real flow through coding-agent-guard, per day or week, to tune its thresholds.

  python stats.py [--log PATH] [--days 7] [--by day|week] [--horizon 0.5] [--screen 0.5]

Reads the hook's log_file (by default the one the project's .claude/coding-agent-guard/settings.json names).
--horizon and --screen are the thresholds the server asks Claude at, for the what-if tables.
Prints counts, rates, scores and timings only; the log holds no text.
"""
import argparse
import collections
import datetime
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
BUCKETS = (0.1, 0.3, 0.5, 0.7, 0.9, 1.01)
FLAG = 0.9


def load(path, days):
    cutoff = datetime.datetime.now().astimezone() - datetime.timedelta(days=days)
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    r = json.loads(line)
                    ts = datetime.datetime.fromisoformat(r["ts"])
                except (ValueError, KeyError, TypeError):
                    # Hooks running at once can tear a line; one torn record must not stop the report.
                    print("stats: skipped an unreadable log line", file=sys.stderr)
                    continue
                if ts >= cutoff:
                    yield ts, r


def scores_of(r):
    """(classifier, screen, judge) scores of one call, the judge being Claude, Codex, agy or a chat model; None where a stage did not run."""
    s = r.get("scores") or {}
    num = {k: v for k, v in s.items() if isinstance(v, (int, float))}
    cls = max((v for k, v in num.items() if not k.startswith("screen:") and k not in ("claude", "codex", "agy", "chat", "judge")),
              default=None)
    scr = max((v for k, v in num.items() if k.startswith("screen:")), default=None)
    return cls, scr, next((num[k] for k in ("claude", "codex", "agy", "chat") if k in num), None)


def period(ts, by):
    if by == "day":
        return ts.date().isoformat()
    year, week, _ = ts.isocalendar()
    return f"{year}-W{week:02d}"


def pct(part, whole):
    return f"{100 * part / whole:5.1f}%" if whole else "    -"


def quantiles(values):
    if not values:
        return "   -   /    -  "
    values = sorted(values)
    return f"{statistics.median(values):6.0f} / {values[min(len(values) - 1, int(0.95 * len(values)))]:6.0f}"


def flow(rows, by):
    """One line per period: how much went through, how much came from outside, what it cost and found."""
    groups = collections.defaultdict(list)
    for ts, r in rows:
        groups[period(ts, by)].append(r)
    print(f"{'period':<11} {'calls in':>8} {'outside':>14} {'to Claude':>15} {'flagged':>8} {'confirmed':>9} "
          f"{'blocked out':>11} {'server down':>11} {'hook ms p50/p95':>16}")
    for key in sorted(groups):
        g = groups[key]
        ins = [r for r in g if r.get("direction") == "in"]
        out = [r for r in g if r.get("direction") == "out"]
        ext = [r for r in ins if r.get("external")]
        claude = [r for r in ext if r.get("claude_asked")]
        print(f"{key:<11} {len(ins):>8} {len(ext):>6} {pct(len(ext), len(ins)):>7} {len(claude):>6} {pct(len(claude), len(ext)):>8} "
              f"{sum(bool(r.get('injection')) for r in ins):>8} {sum(bool(r.get('confirmed')) for r in g):>9} "
              f"{sum(bool(r.get('blocked')) for r in out):>11} {sum(bool(r.get('classifier_error')) for r in ext):>11} "
              f"{quantiles([r['hook_ms'] for r in ext if 'hook_ms' in r]):>16}")


def distribution(outside):
    """How outside texts spread over the score range, per stage: where the thresholds cut."""
    print(f"\n{'score':<12}" + "".join(f"{f'<{b:.1f}' if b <= 1 else '0.9-1.0':>10}" for b in BUCKETS))
    for label, index in (("classifier", 0), ("screen", 1)):
        values = [s[index] for s in map(scores_of, outside) if s[index] is not None]
        counts, low = [], 0.0
        for b in BUCKETS:
            counts.append(sum(low <= v < b for v in values))
            low = b
        print(f"{label:<12}" + "".join(f"{c:>10}" for c in counts) + f"   ({len(values)} scored)")


def at(scored, h, sc):
    """What Claude would see with the classifier threshold h and the screen threshold sc (None: no screen)."""
    asks = lambda s: (s[0] is not None and s[0] >= h) or (sc is not None and s[1] is not None and s[1] >= sc)
    sent = [s for s in scored if asks(s)]
    return {"sent": len(sent),
            # would go to Claude but never did, so its verdict is unknown (a flag at 0.9 needs none)
            "never_judged": sum(s[2] is None and not (s[0] is not None and s[0] >= FLAG) for s in sent),
            "kept": sum(s[2] == 1.0 for s in sent), "confirmed": sum(s[2] == 1.0 for s in scored)}


def what_if(outside, horizon, screen, days):
    """Claude's workload and the confirmed injections kept at other thresholds, from the real scores."""
    scored = [scores_of(r) for r in outside]

    def row(label, h, sc, current):
        r = at(scored, h, sc)
        unknown = f"  never judged {r['never_judged']}" if r["never_judged"] else ""
        print(f"  {label:<24} to Claude {r['sent']:>5} ({r['sent'] / max(days, 1):6.1f}/day){unknown:<20} "
              f"keeps {r['kept']:>3}/{r['confirmed']} of Claude's confirmed injections{'   <- now' if current else ''}")

    print(f"\nWhat-if, over {len(outside)} outside reads ({at(scored, 0, None)['confirmed']} that Claude called injections):")
    print(f" classifier threshold, screen at {screen}:")
    for h in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        row(f"classifier >= {h}", h, screen, h == horizon)
    print(f" screen threshold, classifier at {horizon}:")
    for sc in (None, 0.5, 0.7, 0.9, 0.99, 0.999):
        row("no screen" if sc is None else f"screen >= {sc}", horizon, sc, sc == screen)


def latency(outside):
    with_claude = [r["hook_ms"] for r in outside if r.get("claude_asked") and "hook_ms" in r]
    without = [r["hook_ms"] for r in outside if not r.get("claude_asked") and "hook_ms" in r]
    server = [r["server_ms"] for r in outside if isinstance(r.get("server_ms"), (int, float))]
    print(f"\nLatency, ms median / p95 (in the hook, after Python starts):")
    print(f"  outside read, no Claude   {quantiles(without)}   ({len(without)})")
    print(f"  outside read, with Claude {quantiles(with_claude)}   ({len(with_claude)})")
    print(f"  scoring server alone      {quantiles(server)}   ({len(server)})")


def sources(outside):
    def where(r):
        if r.get("host"):
            return r["host"]
        if r.get("jira"):
            return "jira " + ",".join(sorted({k.split("-")[0] for k in r["jira"]}))
        return " ".join(r.get("programs") or [r.get("tool", "?")])
    for label, pick in (("sent to Claude", lambda r: r.get("claude_asked")), ("flagged", lambda r: r.get("injection"))):
        top = collections.Counter(where(r) for r in outside if pick(r)).most_common(5)
        print(f"\nTop sources {label}: " + (", ".join(f"{k} {n}" for k, n in top) if top else "none"))


def project_log():
    """log_file of the nearest project above the current directory, as the hook would resolve it."""
    import guard
    here = os.getcwd()
    while not os.environ.get("CLAUDE_PROJECT_DIR"):
        if os.path.isfile(os.path.join(here, guard.CONFIG)):
            os.environ["CLAUDE_PROJECT_DIR"] = here
        elif os.path.dirname(here) == here:
            break
        here = os.path.dirname(here)
    log = guard.load_config()["log_file"]
    return guard._project_path(log) if log else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", help="log file; default: log_file from the project's .claude/coding-agent-guard/settings.json")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--by", choices=["day", "week"], default="day")
    ap.add_argument("--horizon", type=float, default=0.5, help="classifier score the server asks Claude at")
    ap.add_argument("--screen", type=float, default=0.5, help="screen score the server asks Claude at")
    args = ap.parse_args()
    path = args.log or project_log()
    if not path or not os.path.exists(path):
        sys.exit(f"no log at {path!r}; set log_file in .claude/coding-agent-guard/settings.json or pass --log")
    rows = list(load(path, args.days))
    if not rows:
        sys.exit(f"no entries in the last {args.days} days of {path}")
    outside = [r for _, r in rows if r.get("direction") == "in" and r.get("external")]
    print(f"coding-agent-guard flow, last {args.days} days, {len(rows)} log lines from {path}\n")
    flow(rows, args.by)
    distribution(outside)
    what_if(outside, args.horizon, args.screen, args.days)
    latency(outside)
    sources(outside)


if __name__ == "__main__":
    main()
