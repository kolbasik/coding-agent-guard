# coding-agent-guard

A plugin for Claude Code, Codex and Antigravity that checks what reaches the
coding agent from outside and what the agent sends out. Codex gets all of it
except output redaction and the transcript scrub, and its ask rules block (see
[Codex](#codex)); Antigravity withholds output that holds a secret instead of
redacting it (see [Antigravity](#antigravity)).

| When | Checks | On a hit |
|---|---|---|
| After a shell, Grep, web or MCP tool runs | Secrets and personal IDs | Redacted before Claude sees the output |
| | Invisible Unicode (zero-width, bidi, tag characters) | Removed |
| | Instruction-like text in output from outside | A note tells Claude it is data |
| Before a call that leaves the machine | Secrets and personal IDs in the call, the files it uploads, the staged diff of a commit, the commits of a push | Blocked, with the kind named and the value never repeated |
| | Instruction-like text and your warn rules in text a person will read | A note, or a block for a rule with `"block": true` |
| | Your ask rules on a shell command line | The user is asked before it runs |
| Before Read, Grep or a shell command such as `cat` opens a file | Credential files: `.env`, cloud and CLI logins, private keys | Refused, with the kind of file named |
| When a Claude Code turn, subagent or session ends | Secrets and personal IDs anywhere in the transcript rows written since the last check: another hook's copy of the raw output, a file Read showed, a pasted prompt | Masked in place with `*` of the same length (see [Transcript scrub](#transcript-scrub)) |

It never checks your own prompts.

## What it detects

- **Secret shapes:** AWS, GitHub, GitLab, Atlassian, Slack, Anthropic, Google,
  Stripe, npm and Jenkins tokens, JWTs, private keys, Azure account keys,
  bearer headers, passwords in URLs, connection strings, YAML and JSON.
  Placeholders such as `${DB_PASSWORD}` or `<password>` are left alone.
- **Known values:** any environment variable whose name contains token, secret,
  password, api key, private key or credential, plus Windows Credential Manager
  entries or macOS keychain generic passwords you list. These match exactly, whatever their shape.
- **Personal IDs:** Finnish henkilötunnus, check character verified.
- **Credential files:** `.env` and `.env.*` (not `.env.example`, `.sample`,
  `.template` or `.dist`), `~/.aws/credentials` and the AWS SSO and CLI caches,
  the GitHub CLI's `hosts.yml`, `~/.git-credentials`, `.netrc`, `*.pem`,
  `*.p12`, `*.pfx`, private SSH keys (`id_rsa`, `id_ed25519`, `id_ecdsa`,
  `id_dsa`; not `.pub`), coding-agent logins (Claude Code's
  `.credentials.json`, Codex's `auth.json`, Gemini's `oauth_creds.json`),
  Docker's `config.json`, `~/.kube/config`, `.pypirc`, `.pgpass` and gcloud's
  credential files. A symlink to one counts as the file itself. Shell commands
  that read one are refused too: `cat`, `head`, `tail`, `less`, `more`, `bat`,
  `grep`, `rg`, `sed`, `awk`, `cut`, `strings`, `xxd`, `base64`, `cp` (its
  source, not its destination), `source` or `.`, and PowerShell's
  `Get-Content`, `gc` and `type`. `ls`, `stat` or `test -f` on one is not, nor
  is `cp .env.example .env`.
- **Injection:** "ignore previous instructions" and variants, fake role tags
  and lines, "don't tell the user", requests to send credentials somewhere,
  hidden tag characters.

Pattern lists are defence in depth, not a guarantee. A reworded injection or a
secret of an unknown shape gets through.

## Install

The easiest way is to let your coding agent do it. Paste this into Claude Code or Codex:

```text
Install coding-agent-guard by following https://raw.githubusercontent.com/kolbasik/coding-agent-guard/main/llms-install.md
```

[`llms-install.md`](llms-install.md) walks the agent through checking Python,
installing the plugin, testing that it blocks and redacts, optional settings
and the optional scoring server. It asks you before it installs software or
picks where suspect text may be sent. To do it by hand instead:

Needs [uv](https://docs.astral.sh/uv/) or Python 3.8+ on `PATH`, and `sh` (on
Windows, the Git Bash Claude Code already uses). With uv, the hook runs through
`uv run` and uv supplies the Python.

Claude Code:

```sh
claude plugin marketplace add kolbasik/coding-agent-guard
claude plugin install coding-agent-guard@kolbasik
```

Inside Claude Code the same is `/plugin marketplace add kolbasik/coding-agent-guard`
then `/plugin install coding-agent-guard@kolbasik`. Restart Claude Code so the
hooks load. Update with `claude plugin update coding-agent-guard@kolbasik`.

Codex reads the same marketplace (tested with Codex 0.162.1):

```sh
codex plugin marketplace add kolbasik/coding-agent-guard
codex plugin add coding-agent-guard@kolbasik
```

Codex runs a plugin's hooks only after you trust them, so start `codex` once
and approve them. See [Codex](#codex) for what differs there.

Antigravity (`agy`) installs it from a clone (tested with agy 1.3.3):

```sh
git clone https://github.com/kolbasik/coding-agent-guard.git
agy plugin install ./coding-agent-guard
```

That copies the clone into `~/.gemini/config/plugins/coding-agent-guard`; after
a `git pull`, install it again to update. See [Antigravity](#antigravity) for
what differs there.

To run it without installing, clone it
(`git clone https://github.com/kolbasik/coding-agent-guard.git`) and register
`scripts/guard.py in` as a `PostToolUse` hook, `scripts/guard.py out` as a
`PreToolUse` hook and `scripts/guard.py scrub` as a `Stop`, `SubagentStop`,
`StopFailure` and `SessionEnd` hook, with the matchers from `hooks/hooks.json`.

**Speed.** The hook starts a Python process on nearly every tool call it checks, so the
interpreter matters more than the code. On Windows ARM64 the `python` on `PATH`
is often the x64 build running under emulation. Measured per local call on one
machine (2026-09-29): 130–146 ms with it, 61 ms with a venv on the native
build. Let uv pick the native build and make the venv next to the scripts:

```sh
uv venv --managed-python --python 3.12 .venv     # in this repo; set UV_PYTHON_INSTALL_DIR to keep the interpreter here too
```

`scripts/run` uses `.venv` when it exists. For a hook registered by hand, name
`.venv/Scripts/python.exe` (Windows) or `.venv/bin/python` as the exec-form
`command`, with `guard.py` in `args`. Asking uv on every call instead
(`uv run --no-project`) adds about 25 ms per call; a precompiled entry saves
only about 4 ms, because Python already caches the bytecode of every imported
module.

## Codex

Codex's `PostToolUse` hook cannot replace a tool's output, so under Codex a
secret in command, web or MCP output reaches the model. The guard still finds
it: the model gets a note not to repeat, store or send it, and you get a
warning (and a desktop notification with `notify: "desktop"`). Everything else
works as under Claude Code: secrets leaving the machine are blocked, and
instruction-like text gets a note. Codex sets no `CLAUDE_PROJECT_DIR`, so the
project settings are found from the session's working folder.

Codex has no file-reading tool of its own: it reads files through the shell,
so the guard refuses a shell command that reads a credential file (`cat .env`,
`source .env`) before it runs, as on every host. Codex treats a hook's "ask" as a failed hook and
runs the call, so an [ask rule](#ask-before-a-command) blocks under Codex
instead, with the same reason; the user runs the command themselves.

The [transcript scrub](#transcript-scrub) does not run under Codex. Codex runs
the plugin's `Stop`, `SubagentStop` and `SessionEnd` hooks too, so they appear
among the hooks to trust, but the guard ends them without reading anything:
Codex's session files keep what the model saw, and their format is not a
stable interface for hooks.

## Antigravity

Antigravity's hooks can neither redact a tool's output nor add a note beside
it, so under `agy` the guard does what they allow (measured with agy 1.3.3 on
2026-10-11):

- Output holding a secret is withheld whole: the model gets only the guard's
  reason and can run the command again so that it prints no values. agy itself
  still shows the raw output in its terminal and keeps it in its step files.
- Notes (instruction-like text in output from outside, warn-rule hits in
  outgoing text) reach the model through agy's `PreInvocation` hook, just before
  its next call. They wait in `~/.claude/coding-agent-guard/agy-pending/`.
- Secrets leaving the machine are blocked as under Claude Code, and the model
  sees the reason. MCP calls are checked as `mcp__<server>__<tool>`, so the
  same `text_tools` and `local_tools` patterns apply.
- Added later and not yet tried in a live agy session: `view_file` and
  `grep_search` refuse credential files as Read and Grep do; `grep_search`
  output holding a secret is withheld whole, as command output is (agy 1.4.7
  saves it as a step file the hook reads); and an ask rule answers
  `force_ask`, which agy's own hook documentation (agy 1.4.7) says prompts even
  for a command the user chose to always allow.
- agy blocks a call, or drops its output, when a hook fails or times out, so
  under agy the guard lets the call through on an internal error.
- The [transcript scrub](#transcript-scrub) does not run under agy: it has no
  hook at the end of a turn, and its step files keep the raw output.

The `PreInvocation` hook starts Python before every model call: about 0.24 s
each on a Windows ARM64 VM with the venv (2026-10-11). agy sets no
`CLAUDE_PROJECT_DIR`; the project settings are found from the session's
workspace folder.

## Configure

Optional. `~/.claude/coding-agent-guard/settings.json` and `<project>/.claude/coding-agent-guard/settings.json`
are read in that order, and every list extends the built-in one.

| Key | Meaning |
|---|---|
| `external_commands` | Regexes for shell commands whose output comes from outside, added to curl, wget, gh, aws, ssh and similar |
| `outbound_commands` | Regexes for shell commands that send data off the machine, added to curl, gh, git commit/push, scp and similar |
| `text_commands` | Outbound commands whose text a person reads; warn rules apply to them |
| `text_tools` | The same for non-shell tools, by tool-name regex |
| `local_tools` | Tool-name regexes whose input stays on this machine, so secret shapes in it are not blocked |
| `trusted_lines` | Regexes for whole lines a tool adds to its own output, such as an update banner or a usage hint, left out of injection checks; a regex must match the entire line, so keep each one as exact as the line |
| `secret_patterns` | Extra `{"name", "pattern"}` secret shapes; a group named `v` marks the secret part |
| `secret_env` | Extra environment variable names whose values are secrets |
| `credential_manager_filters` | Name filters whose values are secrets, e.g. `"myapp/*"`: Windows Credential Manager target names, or on macOS keychain generic-password service names, read through `/usr/bin/security` (so only items that trust it, such as ones it wrote, are read without a prompt; an ssh session cannot read them) |
| `warn` | `{"name", "pattern", "message"?, "commands"?, "block"?}` rules for outgoing text; `commands` limits a rule to matching commands, `"block": true` denies the call instead of adding a note |
| `ask_commands` | `{"name", "pattern", "message"?}` rules for shell commands the user must approve first; see [Ask before a command](#ask-before-a-command) |
| `credential_files` | Extra `{"name", "pattern"}` credential files that Read and Grep refuse; the regex is searched, ignoring case, in the file's absolute path with `/` separators, e.g. `"/\\.vault-token$"` |
| `allowed_credential_files` | Regexes, matched the same way, for paths to read even though they look like a credential file, such as a test fixture: `"/tests/fixtures/[^/]+\\.pem$"` |
| `classifier_url` | Base URL of a scoring server (below); empty turns the model check off |
| `classifier_threshold` | Score at or above which a model flags the output; default `0.9` |
| `classifier_timeout` | Seconds to wait for the server before falling back to patterns; default `5`. Keep it at 40 or less: the output hook is stopped after 60 s, and a stopped hook drops its redactions too |
| `classifier_token_env` | Environment variable holding the server's bearer token; default `CODING_AGENT_GUARD_TOKEN` |
| `log_file` | JSON Lines file with one line per checked call (relative paths resolve against the project); empty turns logging off |
| `samples_file` | JSON Lines file keeping the redacted text of outputs flagged as injections, up to 50,000 characters each; empty (default) keeps none |
| `notify` | `"desktop"` pops a notification for confirmed findings; `"none"` (default) only shows the line in Claude Code |
| `transcript_scrub` | `true` (default) masks secrets found in the Claude Code transcript; `false` only finds them and logs the kinds and counts |

The four `classifier_*` keys, `log_file`, `samples_file`, `notify` and `transcript_scrub` replace the default rather than extending it.

**Notifications and the log.** A *confirmed* finding is a blocked secret or
personal ID, or an injection a model flagged and the Claude judge did not clear.
It shows a warning line to the user in Claude Code (`systemMessage`) and, with
`notify: "desktop"`, a Windows toast, macOS notification or `notify-send`.
A flag the judge could not check because it failed is not confirmed; instead
the user sees one line an hour saying the judge is failing, with its error.
`log_file` gets one line per call: every tool output, every outgoing call, and
anything with a finding (redactions, pattern hits, cleared flags, blocks,
warnings, an unreachable server), with its time, session, tool, program names,
Jira keys, URL host, scores, whether Claude was asked, and how long the hook
took; and one line per [transcript scrub](#transcript-scrub) that found
something. The text is kept only as its length and a hash of its redacted form; no
text and no secret is written.

**Flagged texts.** With `samples_file` set, the redacted text of every output a
model or pattern flagged as an injection is kept there, linked to its log line
by `sha256`, so false alarms and real attacks can be studied later. Unflagged
text is never kept. The file holds real attacks and whatever the flagged source
contained, so keep it out of version control and do not open it in Claude Code:
the Read tool does not redact it.

**Stats.** `python scripts/stats.py [--days 7] [--by day|week]` reads the log
and prints, per day or week, how many calls came in and from outside, how many
went to Claude, were flagged, confirmed or blocked, and the hook's latency; how
outside texts spread over the score range; and a what-if table showing how many
texts Claude would see, and how many of its confirmed injections would be kept,
at other classifier and screen thresholds. It prints numbers only.

```json
{
  "external_commands": ["jira-cli"],
  "outbound_commands": ["jira-cli"],
  "text_commands": ["jira-cli"],
  "credential_manager_filters": ["myapp/*"],
  "warn": [{ "name": "internal-host", "pattern": "\\.corp\\.internal\\b", "message": "names an internal host" }]
}
```

## Ask before a command

An ask rule makes the host ask the user before a shell command runs, showing
the rule's message. None ship by default; some to start from:

```json
{
  "ask_commands": [
    { "name": "force-push", "pattern": "git\\s+(?:-C\\s+\\S+\\s+)?push\\b(?=.*\\s(?:-f|--force\\S*|\\+\\S+)(?:\\s|$))(?=.*[\\s:+](?:main|master)(?:\\s|$))", "message": "force-pushes to main or master" },
    { "name": "reset-hard", "pattern": "git\\s+(?:-C\\s+\\S+\\s+)?reset\\b.*\\s--hard\\b", "message": "discards uncommitted changes" },
    { "name": "clean", "pattern": "git\\s+(?:-C\\s+\\S+\\s+)?clean\\b.*\\s(?:-[a-zA-Z]*f|--force)", "message": "deletes untracked files" },
    { "name": "rm-rf", "pattern": "rm\\s+-(?=[a-zA-Z]*[rR])(?=[a-zA-Z]*f)[a-zA-Z]+\\s+(?!(?:/tmp/|/private/tmp/|\"?\\$\\{?TMPDIR\\b))", "message": "deletes a folder outside a temp folder" },
    { "name": "terraform-apply", "pattern": "(?:terraform|tofu)\\b.*\\s(?:apply|destroy)\\b", "message": "changes infrastructure" },
    { "name": "read-secret", "pattern": "aws\\b.*\\bsecretsmanager\\s+get-secret-value\\b", "message": "reads a secret value" },
    { "name": "aws-prod", "pattern": "AWS_PROFILE=\\S*prod|aws\\b.*--profile[\\s=]+\\S*prod", "message": "uses a production AWS profile" }
  ]
}
```

- `pattern` must match from the start of a command as it runs: after `;`,
  `&&`, `|` or inside `$( )`, as written (so `AWS_PROFILE=prod aws ...` is
  seen) and again without `rtk`, `sudo`, `env`, `timeout` and `VAR=x`, and
  inside `bash -c` or `pwsh -Command`. A command named in a quoted string, a
  heredoc or an argument (`echo "git push -f"`) is not run, so it is not
  matched. `.*` can still run into a quoted argument, which is why the git
  rules above name the subcommand right after `git`.
- It sees only the command line: `git push -f` with no branch named, or a
  profile set by an earlier `export`, is not matched.
- A secret or a `"block": true` rule denies the call before any ask.
- Claude Code (tried with 2.1.318 on 2026-11-06, a hook answering "ask" for
  `echo`): an interactive session in `auto` mode still showed the permission
  prompt with the reason, and Claude Code's hooks documentation says the
  auto-mode classifier does not decide such a call. Under `claude -p`, in the
  default and in `auto` mode and with `--allowedTools Bash`, nobody can answer,
  so the call was denied and the model got the reason. `bypassPermissions` was
  not tried.
- Codex and Antigravity: see their sections above.

## Optional: a model-based check

Patterns miss reworded injections. A small classifier catches more, but
loading one costs seconds, so it runs as a long-lived server, on your machine
or on another one with more memory. Output from outside is sent to it
already redacted, and a score over the threshold adds to Claude's note. If the
server is down, the hook falls back to patterns and the call goes through.

On the server machine, from a copy of this repo (needs [uv](https://docs.astral.sh/uv/);
everything stays inside the repo folder):

```sh
sh scripts/setup-server.sh
.venv/bin/python scripts/server.py --model models/horizon-guard-base \
    --host <address the client reaches> --port 8765
```

On Windows, run the setup from Git Bash and start `.venv/Scripts/python.exe`
instead; the script prints the right command. On the same machine as the
agent, use `127.0.0.1` for the address on both sides.

Set `CODING_AGENT_GUARD_TOKEN` on both sides to require a bearer token.

On an Apple silicon Mac, `sh skills/coding-agent-guard/scripts/setup-mac.sh --host <address>`
does all of the above plus Ollaya (pinned `v0.7.5`, checksums verified; an installed
copy of that version is reused) with `laya:en`, and installs two LaunchAgents so
Ollaya and the server start at login and restart if they stop. Add
`--claude-model claude-sonnet-5 --claude-token-file <file>` for the Claude judge, or
`--chat-model gemma4:cloud` (with Ollama running there) to judge with an Ollama model
instead, or `--agy-model gemini-3.8-flash-low` (with `agy` installed and signed in there),
and `--codex-model gpt-6.1-sol` (with the `codex` CLI installed and logged in
there) to judge text from Codex sessions with Codex. Add `--ollama-model clef:cloud`
(with Ollama running there and signed in) to also score every text with clef, and
`--anonymize <company or product name>` once per name to keep out of what it reads.
It is safe to run again.

### Which model

Measured with `bench/score.py` on 2026-09-29, on held-out test splits only:

| Model | deepset caught | xTRam1 caught | False alarms, published benign | False alarms, our tickets and notes |
|---|---|---|---|---|
| Horizon-Labs prompt-injection-guard-base, 0.5 | 65% | 80.5% | 0.7% | 3–10% |
| same, 0.9 | 38% | 56% | 0.4% | 3.3% |
| Prompt Guard 2 86M, full precision, 0.5 | 17% | 46% | 0.2% | 0–2% |

Horizon-Labs (Apache-2.0, ungated) is the default. Its training data includes
`deepset` train and all of NVIDIA's indirect-injection set, so scores on those
sets mean nothing for it; the table uses what it did not see. It was six days
old when measured and its publisher's own benchmarks are unaudited. At 0.5 its
false alarms on real tickets are too noisy on their own, which is what the judge
below is for.

How the pieces combine, on the same held-out sets plus
[AgentInjectionBench](https://huggingface.co/datasets/ppradyoth/AgentInjectionBench)
(142 injections inside tool output, 40 attack-adjacent benign controls; not in
Horizon-Labs' training data), measured 2026-09-29:

| Setup | Caught: deepset / xTRam1 / AgentInjectionBench | False alarms, our texts | Our texts sent to Claude |
|---|---|---|---|
| Horizon-Labs alone, 0.9 | 38% / 56% / 65% | 2.5% | – |
| Horizon-Labs → `--confirm laya:en` | 48% / 75.5% / 67% | 3.3% | 3% (to annotate) |
| Horizon-Labs 0.5 or more → Claude | 65% / 80.5% / 70% | 2.5% | 5% |
| **Horizon-Labs 0.5 or `--screen laya:en` 0.5 or more → Claude** | **83% / 94% / 79%** | 2.9% | 40% |

The last row is what `setup-mac.sh` installs when a Claude judge is given. On
AgentInjectionBench every setup raised the same 6 false alarms of 40, all from
Horizon-Labs at 0.9 or more; Claude cleared 5 of them, so 1 reached the user as
a notification. Claude's verdicts across these runs: every injection it was
shown kept, 26 of 27 benign texts cleared.

On the client, set `classifier_url` to `http://<that address>:8765` and put the
same token in the `CODING_AGENT_GUARD_TOKEN` environment variable.

- `fetch_model.py` downloads only ungated models, at a pinned revision, and
  checks every large file against the hub's SHA-256.
- Any ONNX sequence classifier with `tokenizer.json` and an `id2label` config
  works; repeat `--model` to run several side by side.
- `--confirm <model>` asks a decision model served by [Ollaya](https://ollaya.dev)
  for a second opinion, only when a classifier scores at least `--confirm-above`
  (default 0.5). With the client's threshold at 0.9 this is a cascade: the
  classifier flags alone when sure, and the second model can flag what it was
  unsure of. Measured on 2026-09-29, Horizon-Labs confirmed by `laya:en` caught
  48% / 75.5% (deepset / xTRam1) against 38% / 56% for Horizon-Labs alone at 0.9,
  with the same false-alarm rate on real tickets (3.3%). `laya:en` on its own
  flagged 20–45% of ordinary tickets and notes, so use it only as a confirmer.
  Other confirmers, same test: `winnow:e4b` 41.7% / 67.2% (363 ms per call on an
  M5 Pro GPU), `decider:4b` 38.3% / 60.2% (2.9 s, CPU), `qwen3guard`, `kev`,
  `jevk5` and `nli` 55.6–58.1% on xTRam1, no better than Horizon-Labs alone.
  `laya:en` or `winnow:e4b` together reach 50.0% / 78.4%. These rates rest on
  60 benign texts per source, and a confirmer's false alarms on the 8 benign
  texts Horizon-Labs was unsure of, so read small differences as noise.
- `--screen <model>` scores every text with a decision model served by Ollaya
  that never flags on its own: at `--screen-above` (default 0.5) it sends the
  text to the Claude judge, and only Claude's verdict can flag it. laya:en
  screens well because it catches attacks Horizon-Labs misses and Claude throws
  out its many false alarms. It needs `--claude-model`, adds about 70 ms to every
  text, and sends roughly 40% of ordinary tickets and notes to Claude.
- `--ollama clef:cloud` scores every text with a decision model served by Ollama
  0.35+ (`--ollama-url`, default the local Ollama) that flags like a classifier:
  0.9 or more raises a flag, and with a judge, `--claude-above` sends what it
  finds suspect to the judge. It reads what a judge would (up to 32,000
  characters), anonymized first: secrets and personal IDs redacted, e-mail
  addresses, URL hosts, home folders, IPs, issue keys, phone numbers and
  business IDs replaced, and every `--anonymize <term>` (company or product
  names) too. People's names are not replaced, and the rest of the text goes
  wherever the model runs: for a `:cloud` model, Ollama's cloud, which by its
  privacy policy (March 2026) processes cloud prompts transiently and does not
  train on them. clef (Cloudflare, 27B) adds about 0.4 s to every text (0.9 s
  p95). Measured 2026-11-06 with Ollama 0.40.15 and the Sonnet 5 judge at
  `--claude-above 0.5`; our own tickets and notes were anonymized before they
  went to the cloud (counts: public is deepset + xTRam1, 301 injections and 615
  benign; AgentInjectionBench 142 and 40; our texts 240 benign):

  | Setup | Caught: public / AgentInjectionBench | False alarms: public / AgentInjectionBench / our texts | Our texts sent to Claude |
  |---|---|---|---|
  | Horizon-Labs + `--screen laya:en` → Claude | 276 / 112 | 20 / 6 / 7 | 89 |
  | **same + `--ollama clef:cloud`** | **285 / 141** | **20 / 6 / 7** (3 more sent to Claude, unjudged) | 92 |
  | `clef:cloud` alone, 0.9 | 127 / 119 | 0 / 0 / 0 | – |

  Claude's extra work is mostly the attacks clef finds: 9 more public texts and
  29 more AgentInjectionBench texts. Anonymizing cost clef no public catch and 1
  of 142 AgentInjectionBench catches at 0.5 (none at 0.9). clef's training data
  is not published, so AgentInjectionBench may flatter it.
- `--claude-model claude-sonnet-5` asks a locked-down `claude -p` about text a classifier
  flags or is unsure of (`--claude-above`, default 0.9; 0.5 lets Claude decide
  Horizon-Labs' unsure band) or that a screen sends: no thinking, tools, settings
  sources, MCP servers, skills or saved session, its own empty config folder and
  working folder, telemetry and update checks off, $0.25 cap. It reads up to
  32,000 characters: all of a shorter text, else the part around the
  classifier's most suspect window, so padding cannot hide an injection from
  it. Its verdict is
  added to the note (`model:claude`, or `claude-judge:ordinary-data`) and never
  removes a classifier's 0.9 warning, because the judge read the suspect text;
  below 0.9 its verdict decides. When the judge fails (a usage limit, a lost
  login), the note says `claude-judge:unavailable` and the user is not alerted:
  the judge clears nearly all of Horizon-Labs' 0.9 flags (353 of 356, live log
  to 2026-11-05). Over ssh the macOS
  keychain is locked, so log it in with `claude setup-token` and
  `--claude-token-file`; `--bare` and `CLAUDE_CODE_SIMPLE` refuse subscription
  logins. Measured 2026-09-29 on 30 flagged injections and 10 flagged benign
  texts: Sonnet without thinking kept 30/30 and cleared 10/10 in 1.9 s (p50);
  Haiku with thinking 28/30 in 5.1 s (up to 25 s); Haiku without thinking 23/30.
  Measured 2026-10-07, thinking off, on the 428 texts a `bench/judge.py --band`
  run sent Claude (280 injections from deepset and xTRam1; 148 benign, 92 of
  them our own tickets and notes):

  | Judge | Injections missed | False alarms | p50 | Slowest |
  |---|---|---|---|---|
  | `claude-sonnet-5` | 6 | 15 | 1.7 s | 4.6 s |
  | `claude-sonnet-5-5` | 21 | 10 | 2.0 s | 14.4 s |
  | `claude-haiku-5-5` | 47 | 8 | 1.6 s | 5.3 s |

  Give a full model ID. `sonnet` and `haiku` are CLI aliases that move when the
  CLI updates: with CLI 2.1.292, `sonnet` means Sonnet 5.5 and `haiku` still
  means Haiku 4.5. When the pinned model is retired, the judge fails and its
  scores show `claude_error`.
- `--codex-model gpt-6.1-sol` judges text from Codex sessions with a locked-down
  `codex exec` instead (no user config, rules, hooks, plugins, ChatGPT apps,
  skills or saved session; the shell, sub-agent and code-mode features off;
  read-only sandbox; reasoning effort low); text from Claude Code sessions still
  goes to Claude. The sandbox stays as the backstop for any tool a later Codex
  adds. Measured 2026-10-10 and 2026-10-11 with
  Codex CLI 0.162.1 on the public band (122 injections, 53 benign texts from
  deepset and xTRam1; our own tickets and notes were not sent to OpenAI;
  `bench/judge.py --band codex-<model> --public-only --also ollaya-laya-en:0.5`):

  | Judge | Injections caught | False alarms | p50 | Slowest |
  |---|---|---|---|---|
  | `claude-sonnet-5` (same texts) | 117 | 13 | 1.7 s | 4.6 s |
  | `gpt-6.1-sol` | 117 | 27 | 5.1 s | 11.0 s |
  | `gpt-5.6-sol` | 103 | 15 | 3.8 s | 12.4 s |
  | `gpt-5.6-terra` | 100 | 15 | 3.7 s | 7.9 s |
  | `gpt-5.6-luna` | 95 | 13 | 3.4 s | 10.9 s |
  | `gpt-6-sol` | 99 | 19 | 3.6 s | 11.9 s |
  | `gpt-6-luna` | 70 | 10 | 3.2 s | 14.5 s |

  These rows were measured before the shell, sub-agents and code mode were
  switched off. Re-run with them off on 2026-10-11, `gpt-6.1-sol` caught 116
  with 31 false alarms (p50 4.8 s, slowest 10.3 s): the same within run-to-run
  noise, since the 5 texts whose verdict changed flip either way when judged
  again, with either set of flags.

  So a Codex judge misses more injections than Claude, or raises more false
  alarms: use it when text from Codex sessions must stay with OpenAI.
  `gpt-6.1-sol` is the suggested model: it caught as many as Sonnet 5 at twice
  the false alarms, and by third-party list prices of 2026-10-04 it costs $2 /
  $10 per million input / output tokens against `gpt-5.6-sol`'s $5 / $30.
  `gpt-6-astra` was only screened on 48 texts of the band (24 of 24 caught, 13
  false alarms of 24). The judge draws on the same ChatGPT usage limit as your
  Codex sessions: once that is used up, scores show `codex_error` until it
  resets, and the classifier's flags still stand.
- `--judge-url` / `--judge-model` add an open-weight LLM as a further opinion,
  through any OpenAI-compatible endpoint (Ollama, LM Studio, llama.cpp).
  `--judge-above 0.5` asks it only when a classifier already scores 0.5 or more,
  so it costs its seconds only on suspect text. `openai/gpt-oss-safeguard-20b`
  (Apache-2.0, ungated, about 14 GB) is built for classifying against a written
  policy; `ibm-granite/granite-guardian-3.3-8b` also takes custom criteria.
  Ollama's cloud models work through the same endpoint. Measured 2026-10-10
  with Ollama 0.40.1 on the public band (122 injections, 53 benign texts from
  deepset and xTRam1; `bench/judge.py --band chat-<model> --public-only`):

  | Judge | Injections caught | False alarms | p50 | Slowest |
  |---|---|---|---|---|
  | `claude-sonnet-5` (same texts) | 117 | 13 | 1.7 s | 4.6 s |
  | `gemma4:cloud` | 117 | 13 | 1.0 s | 4.1 s |
  | `glm-5.3:cloud` | 115 | 17 | 8.1 s | 67.7 s |
  | `deepseek-v4.1-flash:cloud` | 117 | 27 | 1.9 s | 7.2 s |
  | `glm-5.3-flash:cloud` | 119 of 121 | 22 | 3.4 s | 120 s (1 timeout) |
  | `deepseek-v4-pro:cloud` | 107 | 19 | 3.4 s | 13.7 s |

  `gemma4:cloud` matched Sonnet 5 on these texts at about half the time. A
  `:cloud` model sends the text to Ollama's cloud, so our own tickets and notes
  were not part of this run.
- `--chat-model gemma4:cloud` makes such a model the judge in Claude's place:
  it decides the same suspect text, reported as the score `chat`, and its
  verdict annotates or confirms a flag exactly as Claude's does. It talks to
  `--chat-url`, by default the local Ollama (`http://127.0.0.1:11434/v1`), and
  every text it judges goes wherever that endpoint sends it; for a `:cloud`
  model that is Ollama's cloud. Codex sessions keep a `--codex-model` judge if
  one is set. `--claude-model` and `--chat-model` are one or the other.
- `--agy-model gemini-3.8-flash-low` makes the Antigravity CLI (`agy`) the
  judge in Claude's place, reported as the score `agy`; Codex sessions keep a
  `--codex-model` judge if one is set. It runs a tool-less custom agent with no
  skills, plugins, rules, MCP servers or hooks, from its own home and workspace
  folders under `.cache/agy-judge`, so nothing from your own agy setup loads.
  The text goes on stdin, every text it judges goes to Google, and the copy agy
  saves of each conversation is deleted once the verdict is in. Measured
  2026-10-11 with agy 1.3.3 on the same public band:

  | Judge | Injections caught | False alarms | p50 | Slowest |
  |---|---|---|---|---|
  | `claude-sonnet-5` (same texts) | 117 | 13 | 1.7 s | 4.6 s |
  | `gemini-3.8-flash-low` | 111 | 18 | 7.9 s | 74.7 s |

  Most of each call is agy starting up. `--claude-model`, `--chat-model` and
  `--agy-model` are one or the other; on macOS the separate home folder is
  untested.
- Models are not bundled. Check a model's licence before sharing it; Prompt
  Guard 2, for one, is under the Llama 4 Community License.

`bench/score.py` compares models on two published datasets
(`deepset/prompt-injections` for direct injections, NVIDIA's
`Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1` for injections planted in
records) and on benign text you point it at, to measure false alarms on your own
traffic. It prints rates only, never sample text.

It also scores decision models: any model an [Ollaya](https://ollaya.dev) server
runs (`--ollaya laya decider:4b qwen3guard ...`) or Ollama 0.35+ serves at
`/v1/systemone` (`--ollama tev1:4b nimble:9b`), asked the same two questions
from laya's guard preset, and laya through its own package (`--laya`). Each run
saves per-sample scores (label, source, score; no text), and
`--combine` then compares "any model", "at least 2", mean score and every
two-model cascade without scoring again. A cascade is what `server.py` does with
`--judge-above`: the first model flags alone when sure and asks the second when
unsure. `--export-benign FILE` copies your benign text into one file for scoring
on another machine with `--benign-file`.

## Transcript scrub

Claude Code saves each session as a JSON Lines transcript under
`~/.claude/projects/`, and it saves every hook's stdout there as written. A
`PostToolUse` hook that replaces a tool's output (this guard, or another
plugin's) carries the raw output in its own stdout, so a secret redacted
before Claude saw it can still land on disk. Read output, which is never
redacted, and pasted prompts land there too.

At the end of every turn (`Stop`, or `StopFailure` when the turn ends in an
API error), every subagent (`SubagentStop`, on its own transcript) and the
session (`SessionEnd`), the guard reads the rows written since its last check
and runs the same checks as on tool output on every string in them, including
strings that hold JSON such as a hook's stdout. Each secret found is
overwritten in place with `*` of the same byte length:

- the file is never renamed, truncated or reordered, and a row is written back
  only when it still parses as JSON;
- only complete lines are read, so a row still being written waits for the next
  check; Claude Code writes the transcript asynchronously, so the last rows of a
  turn can wait for the next turn or the end of the session;
- the guard keeps how far it has read in one small file per transcript in
  `~/.claude/coding-agent-guard/scrub/`; deleting it makes the next check read
  that transcript from the start again;
- Claude Code gives `SessionEnd` hooks 1.5 s in all, so rows a stopped check
  did not reach are scrubbed when the session is resumed;
- with `log_file` set, each check that finds something adds one line with the
  kinds and counts, never the values; with `transcript_scrub: false` the guard
  only does that and leaves the transcript as written.

**Cost** on an Apple silicon Mac with uv (2026-11-06, median of 20): 53 ms at
the end of a turn that wrote 120 KB of rows, 38 ms when nothing new was written
(a `SessionEnd` right after a `Stop`).
The first check of an existing transcript reads all of it, once: 0.6 s for a
5 MB one, 8 s for a 99 MB one.

Checked in a real `claude -p` session (Claude Code 2.1.319, 2026-11-06): a
fake token a Read showed was masked in both rows that kept it, and every row
still parsed. Not tried: Windows, and whether the API accepts a resumed
session whose earlier thinking text was masked.

## Behaviour to know

- **Fail-open.** A guard error lets the call through and prints
  `coding-agent-guard: internal error ... this call was not checked`.
- **Notes on outgoing text arrive after the call.** Secrets, personal IDs and
  `"block": true` rules are the only things stopped beforehand; ask rules wait
  for the user.
- **Rules see the text a person reads**: the command minus arguments that name
  local files or folders, plus body files. Not the tool's description field,
  and not a commit's code, so a rule never trips on an upload path or a diff.
- **Read is not redacted**, so Claude can still get a file's exact bytes to
  edit it. Credential files are refused instead, before they are opened, and
  so is Grep when its path or glob names one. Grep's output is redacted like a
  command's, since edits take Read's bytes; a Grep over a whole folder is not
  refused, but what it prints is redacted.
- **Cost:** about 200 ms per checked call when Python is started directly,
  plus about 100 ms for the `sh` launcher the plugin uses. A Read or Grep
  that cannot name a credential file is answered by the launcher without
  starting Python: its path and the folder it really sits in hold none of the
  words built-in credential files have in their paths, and no settings file
  sets `credential_files` or `allowed_credential_files`; anything unsure goes
  to Python. Median of 20 Read calls on an Apple silicon Mac with uv
  (2026-11-06): 14 ms answered by the launcher, against 40 ms through Python.
- **Commands count where they run, not where they are mentioned**: after `;`,
  `&&`, `|` or inside `$( )`, behind `rtk`, `sudo`, `env`, `timeout` or `VAR=x`,
  as a path or through PowerShell's `&`, and inside `bash -c` or `pwsh -Command`.
  A name inside a heredoc, a quoted string or an argument (`grep ssh notes.md`) does not.
- **A local command** is blocked only for a known secret value. Secret shapes
  in a command that does not leave the machine (`echo`, a build) pass.

## Privacy skill

The plugin also ships a `privacy` skill (`coding-agent-guard:privacy` once
installed) for macOS: which switch turns off each tool's telemetry, surveys,
update checks and debug logging, how to assess a new tool by watching its
sockets, and a checker that proves the switches are off.

```sh
pwsh -NoProfile -File skills/privacy/scripts/Test-Privacy.ps1                 # status, changes nothing
pwsh -NoProfile -File skills/privacy/scripts/Test-Privacy.ps1 -Action apply   # fix what it can, with backups
```

It needs PowerShell 7. Each check applies only when its tool is installed, and
a sweep flags installed tools nobody has assessed. Add your own assessed tools,
and corporate software that must be left alone, to
`~/.claude/coding-agent-guard/privacy-known.txt`, one `-like` pattern per line.
The environment opt-outs live in `skills/privacy/opt-outs.zsh`, for
`~/.zprofile` to source from the marketplace checkout; the skill's `SKILL.md`
has the details.

## Test

```sh
python -m unittest discover -s tests
pwsh -NoProfile -Command "Invoke-Pester skills/privacy"     # Pester 4.10: Install-Module Pester -RequiredVersion 4.10.1
```
