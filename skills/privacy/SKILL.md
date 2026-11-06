---
name: privacy
description: Telemetry, usage analytics, surveys, crash reports, needless update checks and debug logging on a Mac - where each switch lives, how to assess a tool before trusting it, and a checker that proves every switch is off. Use when installing, updating or first launching any app, CLI, plugin or service; when a tool's analytics, feedback prompt, phone-home or log upload comes up; before touching DO_NOT_TRACK or any opt-out; and when the user asks whether a tool sends data.
argument-hint: "[status | apply]"
---

# Privacy on the Mac

The goal: every telemetry stream, survey, needless update check, debug log and
log upload off, in every app and tool. `scripts/Test-Privacy.ps1`, beside this
file, checks all of it and is the list: each check names the file and key it
reads, and applies only when its tool is installed.

## 1. Check and fix

Needs PowerShell 7 (`brew install --cask powershell`). From this skill's folder:

```bash
pwsh -NoProfile -File scripts/Test-Privacy.ps1                 # status, changes nothing
pwsh -NoProfile -File scripts/Test-Privacy.ps1 -Action apply   # fix what it can
```

Each line is `ok`, `VIOLATION` (with its fix), `n/a` (not installed),
`manual` (only the app's own settings can change it) or `REVIEW` (installed,
never assessed). Exit 0 only with no VIOLATION and no REVIEW. `apply` backs a
file up as `<file>.bak-<timestamp>` before changing it, and leaves a GUI app's
config alone while that app runs. Apply rewrites JSON through `ConvertTo-Json`,
which reformats it and drops JSONC comments; the backup keeps the original.

Tests (Pester 4.10, from the repo root):
`pwsh -NoProfile -Command "Invoke-Pester skills/privacy"`.

## 2. Env opt-outs

`opt-outs.zsh`, beside this file, exports the environment opt-outs. Source it
from `~/.zprofile` through a path that survives plugin updates:

```zsh
source "$HOME/.claude/plugins/marketplaces/kolbasik/skills/privacy/opt-outs.zsh"
```

That is the marketplace checkout, a git clone of this repo
(`kolbasik` is the marketplace name the README installs from; check with
`ls ~/.claude/plugins/marketplaces/`). A clone of the repo elsewhere works
too. Never source it from `~/.claude/plugins/cache/...`: that path names one
plugin version and is deleted once the plugin updates, and the opt-outs go
with it, silently. `apply` writes the marketplace path when it runs from the
cache.

The checker reads a clean login shell, so a copy pasted into `~/.zprofile`
passes too. The variables reach terminals and an agent's tool shells only;
apps opened from the Dock and launchd agents never see them, so those get
their own config (the checks), and a launchd service gets the variables in its
plist.

## 3. Assessing a new tool

A new tool is assessed before it is trusted. Until then the checker's sweep
shows it as `REVIEW`.

1. **Read first, run later.** Read its docs or source for telemetry, crash
   reports, update checks and log upload, and for the variable or config key
   that turns each off. Set the opt-out before the first run: even `--version`
   can phone home.
2. **Trust sockets over code reading.** A code audit of a local proxy missed
   onnxruntime's telemetry; only watching the live process caught it. Run the
   tool's normal work behind a proxy trap, which shows every request that
   honours the proxy variables:

   ```bash
   nc -lk 127.0.0.1 18080 &      # prints each request, answers none
   HTTPS_PROXY=http://127.0.0.1:18080 HTTP_PROXY=http://127.0.0.1:18080 ALL_PROXY=http://127.0.0.1:18080 <tool> <its usual work>
   ```

   and, for clients that ignore those variables, poll its sockets while it
   works: `lsof -nP -a -i -p <pid>`, once a second.
3. **Record the result.** A switch becomes a check in the script
   (`New-JsonCheck`, `New-TomlCheck`, `New-KeyValueCheck`, or `New-Check` for
   anything else) or an export in `opt-outs.zsh`; a tool with nothing to turn
   off goes in your known file (§4), with the reason as a comment.

## 4. Your own known tools

The sweep lists what brew, npm, uv, `~/.local/bin` and `/Applications` hold
and flags every name no check or known pattern covers. The script knows the
tools it checks and those assessed here; add your own in
`~/.claude/coding-agent-guard/privacy-known.txt` (beside the guard's
`settings.json`), or pass another file with `-KnownFile <file>`:

```text
# One -like pattern per line; # starts a comment, anywhere on the line.
some-cli           # source read, proxy trap opened no socket
Example VPN*       # corporate-managed, never touched
```

A missing file adds no names. List here, too, the software you must leave
alone: corporate-managed security and device-management software, VPN clients
and managed browsers. Switching their telemetry or logging off tampers with
security tooling, so they are never touched, only kept out of the sweep.

## 5. Rules

- **`DO_NOT_TRACK=1`, never `true`.** Atlassian's `twg` CLI reads only `"1"`,
  and the same check gates its log upload.
- **Logs:** debug and verbose logging and every log upload are off; normal
  local error logs stay, or a crash cannot be diagnosed.
- **Edit an app's settings only while it is closed.** A running app saves its
  in-memory settings over the file. Re-run §1 after its next launch.
- **Managed settings win.** An organisation's managed settings for Claude Code
  (for example `~/.claude/remote-settings.json`) can turn telemetry back on,
  such as OTEL metrics to the organisation's own collector. That is policy:
  user settings cannot override it, and the checker does not read it.

## 6. Side effects of the switches

- Claude Code `DISABLE_TELEMETRY` also stops feature flags: no advisor tool,
  artifact comments, `/skill-doctor` or skills synced from claude.ai.
- Codex reads `check_for_update_on_startup` only as a root key above the first
  `[table]`; written below one, it silently belongs to that table.

## 7. Only the app can switch these

The checker reads them but cannot set them: Orca → Settings → Privacy →
telemetry (PostHog) off, and Parallels → Preferences → General → Check for
updates and Download updates automatically, both off. The Antigravity app's
Settings → Account → Enable Telemetry is account-level and unreadable here, so
it is always a `manual` line while the app is installed.

## 8. No off switch exists

Update checks in `twg`, `agy`, Orca, Ollama and the Herdr app
(hourly, app and herdr-core); SourceGit's Gravatar lookups (an MD5 of each
commit email); uv's platform user agent.

## When this skill fails

Add each new failure here as symptom → guard, and put the guard into the step
it protects.

- **twg kept sending analytics with `DO_NOT_TRACK=true`.** Guard: §5, `1` only.
- **onnxruntime telemetry missed by a static audit.** Guard: §3, sockets.
- **agy dropped `enableTelemetry` seconds after it was written**: a running agy
  saved its in-memory settings over the file, and the report said "off" while
  telemetry was on for a day. Guard: §5, edit settings only while the app is
  closed, and re-run §1 after its next launch.
- **`brew cat <formula>` turned Homebrew developer mode on** during research.
  Guard: `brew developer off` after any `brew cat`.
