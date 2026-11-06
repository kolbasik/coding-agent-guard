#!/bin/sh
# Set up the coding-agent-guard scoring server on an Apple silicon Mac so it runs after every
# login and restart: Ollaya (pinned and checksum-verified; an installed copy of the same
# version is reused) with laya:en, the Python environment and the Horizon-Labs model,
# and two LaunchAgents that start Ollaya and the server at login and restart them if
# they stop. Safe to run again.
#
#   sh setup-mac.sh [--host 127.0.0.1] [--port 8765] [--claude-model claude-sonnet-5] [--claude-token-file PATH]
#                   [--chat-model MODEL] [--agy-model MODEL] [--codex-model MODEL]
#                   [--ollama-model MODEL [--anonymize TERM ...]]
#
#   --host               address the server listens on; the one clients reach (a VM on this
#                        Mac reaches the Parallels bridge, e.g. 10.211.55.2)
#   --claude-model       also judge flagged text with a locked-down `claude -p`; a full model ID, since aliases move
#   --claude-token-file  file holding a `claude setup-token` token, if the keychain is not usable
#   --chat-model         judge with this Ollama model instead of Claude, e.g. gemma4:cloud; needs Ollama
#                        running on 127.0.0.1:11434 (and signed in, for a :cloud model)
#   --agy-model          judge with a locked-down Antigravity CLI run instead of Claude, e.g.
#                        gemini-3.8-flash-low; needs the agy CLI on your login PATH, signed in
#   --codex-model        judge text from Codex sessions with a locked-down `codex exec` instead; needs the
#                        codex CLI on your login PATH, logged in
#   --ollama-model       also score every text with this Ollama decision model, e.g. clef:cloud; it flags like a
#                        classifier and reads the text anonymized; needs Ollama on 127.0.0.1:11434
#   --anonymize          a company or product name to replace in text sent to --ollama-model; repeat for several
#
# Everything stays in this repo copy except the two LaunchAgents and Ollaya's model store.
set -eu

OLLAYA_VERSION=v0.7.5
OLLAYA_SHA256=7c7d79cae9256d79aa93111f28d2ad24f124c3d730c6786d27694fcef143a437      # ollaya-darwin-arm64.tgz
OLLAYA_MLX_SHA256=cba9a87db03b47bb58964af320e4a2c7ee6b8bc1521aec51f44f7db93ddda6da  # ollaya-darwin-arm64-mlx.tgz
CONFIRM_MODEL=laya:en

HOST=127.0.0.1 PORT=8765 CLAUDE_MODEL="" TOKEN_FILE="" CODEX_MODEL="" CHAT_MODEL="" AGY_MODEL="" OLLAMA_MODEL="" ANONYMIZE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST=$2; shift 2 ;;
        --port) PORT=$2; shift 2 ;;
        --claude-model) CLAUDE_MODEL=$2; shift 2 ;;
        --claude-token-file) TOKEN_FILE=$2; shift 2 ;;
        --chat-model) CHAT_MODEL=$2; shift 2 ;;
        --agy-model) AGY_MODEL=$2; shift 2 ;;
        --codex-model) CODEX_MODEL=$2; shift 2 ;;
        --ollama-model) OLLAMA_MODEL=$2; shift 2 ;;
        --anonymize) ANONYMIZE="$ANONYMIZE$2
"; shift 2 ;;
        -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done
if [ "$(printf '%s' "${CLAUDE_MODEL:+x}${CHAT_MODEL:+x}${AGY_MODEL:+x}" | wc -c)" -gt 1 ]; then
    echo "--claude-model, --chat-model and --agy-model all judge the same text; pick one" >&2; exit 2
fi

[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || { echo "needs an Apple silicon Mac" >&2; exit 1; }
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
AGENTS=$HOME/Library/LaunchAgents
DOMAIN=gui/$(id -u)
LOGS=$REPO/.cache
mkdir -p "$LOGS" "$AGENTS"

step() { printf '\n== %s\n' "$*"; }

wait_port() {   # host port seconds
    i=0
    until nc -z "$1" "$2" 2>/dev/null; do
        i=$((i + 1)); [ "$i" -lt "$3" ] || return 1; sleep 1
    done
}

xml() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

# A LaunchAgent that starts at login, restarts on exit and logs to $LOGS/<log>.log.
agent() {   # label log program [arguments...]
    label=$1 log=$2; shift 2
    file=$AGENTS/$label.plist
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        echo '<plist version="1.0"><dict>'
        echo "  <key>Label</key><string>$label</string>"
        echo '  <key>ProgramArguments</key><array>'
        for arg in "$@"; do echo "    <string>$(xml "$arg")</string>"; done
        echo '  </array>'
        echo "  <key>WorkingDirectory</key><string>$(xml "$REPO")</string>"
        echo '  <key>RunAtLoad</key><true/>'
        echo '  <key>KeepAlive</key><true/>'
        echo '  <key>ThrottleInterval</key><integer>15</integer>'
        echo "  <key>StandardOutPath</key><string>$(xml "$LOGS/$log.log")</string>"
        echo "  <key>StandardErrorPath</key><string>$(xml "$LOGS/$log.log")</string>"
        echo '</dict></plist>'
    } > "$file"
    plutil -lint "$file" >/dev/null
    if launchctl print "$DOMAIN/$label" >/dev/null 2>&1; then
        launchctl bootout "$DOMAIN/$label" 2>/dev/null || true
        i=0; while launchctl print "$DOMAIN/$label" >/dev/null 2>&1 && [ "$i" -lt 10 ]; do i=$((i + 1)); sleep 1; done
    fi
    launchctl bootstrap "$DOMAIN" "$file"
    echo "$label loaded from $file"
}

step "uv"
UV=$(command -v uv 2>/dev/null || true)
if [ -z "$UV" ] && [ -x "$REPO/.bin/uv" ]; then UV=$REPO/.bin/uv; fi
if [ -z "$UV" ]; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$REPO/.bin" UV_NO_MODIFY_PATH=1 INSTALLER_NO_MODIFY_PATH=1 sh
    UV=$REPO/.bin/uv
fi
PATH="$(dirname "$UV"):$PATH"; export PATH   # setup-server.sh calls uv by name
uv --version

step "Ollaya $OLLAYA_VERSION"
OLLAYA=""
for candidate in "$(command -v ollaya 2>/dev/null || true)" /usr/local/bin/ollaya "$REPO/.ollaya/bin/ollaya"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ] && "$candidate" --version 2>/dev/null | grep -q "${OLLAYA_VERSION#v}"; then
        OLLAYA=$candidate; break
    fi
done
if [ -n "$OLLAYA" ]; then
    echo "using $OLLAYA"
else
    tmp=$(mktemp -d "$LOGS/ollaya-download.XXXX")
    base=https://github.com/ollaya-dev/ollaya/releases/download/$OLLAYA_VERSION
    fetch() {   # archive sha256: download, verify, unpack into $REPO/.ollaya
        curl -fsSL -o "$tmp/$1" "$base/$1"
        echo "$2  $tmp/$1" | shasum -a 256 -c - >/dev/null || { echo "checksum mismatch for $1; not installed" >&2; rm -rf "$tmp"; exit 1; }
        mkdir -p "$REPO/.ollaya" && tar -xzf "$tmp/$1" -C "$REPO/.ollaya"
    }
    fetch ollaya-darwin-arm64.tgz "$OLLAYA_SHA256"
    fetch ollaya-darwin-arm64-mlx.tgz "$OLLAYA_MLX_SHA256"   # the Apple GPU runtime laya uses
    rm -rf "$tmp"
    OLLAYA=$REPO/.ollaya/bin/ollaya
    "$OLLAYA" --version
fi

step "login item for Ollaya"
agent dev.coding-agent-guard.ollaya ollaya "$OLLAYA" serve
if ! wait_port 127.0.0.1 11435 60; then
    echo "Ollaya is not listening on 127.0.0.1:11435; see $LOGS/ollaya.log" >&2
    echo "If another Ollaya (the desktop app, say) holds the port, quit it and run this again." >&2
    exit 1
fi

step "Ollaya model $CONFIRM_MODEL"
"$OLLAYA" pull "$CONFIRM_MODEL"

step "Python environment and Horizon-Labs model"
sh "$REPO/scripts/setup-server.sh"

step "login item for the scoring server"
set -- "$REPO/.venv/bin/python" -u "$REPO/scripts/server.py" --model "$REPO/models/horizon-guard-base" \
    --host "$HOST" --port "$PORT"
if [ -n "$CLAUDE_MODEL" ] || [ -n "$CHAT_MODEL" ] || [ -n "$AGY_MODEL" ]; then
    # With a judge: laya:en screens every text and the judge decides everything either model finds
    # suspect (Horizon-Labs 0.5 or more, or laya:en 0.5 or more), the most accurate setup measured.
    set -- "$@" --screen "$CONFIRM_MODEL" --screen-above 0.5 --claude-above 0.5
    if [ -n "$CHAT_MODEL" ]; then
        set -- "$@" --chat-model "$CHAT_MODEL"
    elif [ -n "$AGY_MODEL" ]; then
        AGY=$(zsh -lc 'command -v agy' 2>/dev/null | tail -1 || true)
        [ -n "$AGY" ] || { echo "--agy-model needs the agy CLI on your login PATH" >&2; exit 1; }
        set -- "$@" --agy-model "$AGY_MODEL" --agy-bin "$AGY"
    else
        CLAUDE=$(zsh -lc 'command -v claude' 2>/dev/null | tail -1 || true)
        [ -n "$CLAUDE" ] || { echo "--claude-model needs the claude CLI on your login PATH" >&2; exit 1; }
        set -- "$@" --claude-model "$CLAUDE_MODEL" --claude-bin "$CLAUDE"
        if [ -n "$TOKEN_FILE" ]; then set -- "$@" --claude-token-file "$TOKEN_FILE"; fi
    fi
else
    # Without one: laya:en is the best second opinion on what Horizon-Labs is unsure of.
    set -- "$@" --confirm "$CONFIRM_MODEL" --confirm-above 0.5
fi
if [ -n "$CODEX_MODEL" ]; then
    CODEX=$(zsh -lc 'command -v codex' 2>/dev/null | tail -1 || true)
    [ -n "$CODEX" ] || { echo "--codex-model needs the codex CLI on your login PATH" >&2; exit 1; }
    set -- "$@" --codex-model "$CODEX_MODEL" --codex-bin "$CODEX"
fi
if [ -n "$OLLAMA_MODEL" ]; then
    set -- "$@" --ollama "$OLLAMA_MODEL"
    old_ifs=$IFS; IFS='
'; set -f   # one term per line, never globbed
    for term in $ANONYMIZE; do set -- "$@" --anonymize "$term"; done
    IFS=$old_ifs; set +f
fi
agent dev.coding-agent-guard.server server "$@"

step "check"
i=0
until curl -fsS "http://$HOST:$PORT/health" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then echo "the server is not answering on $HOST:$PORT; see $LOGS/server.log" >&2; exit 1; fi
    sleep 1
done
echo
echo "Done. Ollaya and the scoring server now start at login and restart if they stop."
echo "Logs: $LOGS/ollaya.log and $LOGS/server.log"
echo "Restart the server: launchctl kickstart -k $DOMAIN/dev.coding-agent-guard.server"
