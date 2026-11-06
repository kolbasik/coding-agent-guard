"""Secret and personal-ID detection: find and redact values that must not be seen or sent.

Never returns a matched value, only its kind, so a caller can report a finding
without repeating the leak.
"""
import re

# A group named v marks the secret part of a match; without one the whole match is the secret.
SECRET_PATTERNS = [
    ("aws-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("aws-secret", r"(?i)aws_secret_access_key\s*[=:]\s*(?P<v>[A-Za-z0-9/+=]{40})"),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("atlassian-token", r"\bATATT[A-Za-z0-9_=-]{20,}"),
    ("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}"),
    ("stripe-key", r"\b[rs]k_live_[0-9A-Za-z]{20,}"),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("jenkins-token", r"\b11[0-9a-f]{32}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"),
    ("azure-account-key", r"AccountKey=(?P<v>[A-Za-z0-9+/=]{40,})"),
    ("bearer-token", r"(?i)\bauthorization:\s*bearer\s+(?P<v>[A-Za-z0-9._~+/-]{20,}=*)"),
    ("url-password", r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:(?P<v>[^/\s@'\"]{3,})@"),
    ("password", r"(?i)\b(?:password|passwd|pwd|client_secret|api_?key|secret_?key)\b\s*[=:]\s*(?P<v>[^\s;'\",}]{6,})"),
    ("password", r"(?i)\"(?:password|passwd|client_secret|api_?key|secret|token|access_token|refresh_token)\"\s*:\s*\"(?P<v>[^\"]{6,})\""),
]
GENERIC = ("password", "url-password")
# ${VAR}, $VAR, %VAR%, <placeholder>, *** masks, a bare identifier/call with no digit in it,
# or a JS template literal built at run time (`...${expr}...`).
PLACEHOLDER = re.compile(r"^(?:[$%<*{]|\[REDACTED)|^[A-Za-z_.-]+(?:\(\))?$|^`[^`]*\$\{")

HETU = re.compile(r"\b(\d{2})(\d{2})(\d{2})[-+A-FU-Y](\d{3})([0-9A-FHJ-NPR-Y])\b")
HETU_CHECK = "0123456789ABCDEFHJKLMNPRSTUVWXY"


def compile_patterns(extra=()):
    """Built-in patterns plus (kind, regex) pairs from config."""
    return [(kind, re.compile(rx)) for kind, rx in [*SECRET_PATTERNS, *extra]]


DEFAULT = compile_patterns()


def _hetu_valid(m):
    dd, mm, yy, n, check = m.groups()
    return 1 <= int(dd) <= 31 and 1 <= int(mm) <= 12 and HETU_CHECK[int(dd + mm + yy + n) % 31] == check


def redact(text, known, patterns=DEFAULT):
    """Return (text, kinds) with known secret values, secret-shaped values and personal IDs replaced."""
    kinds = []
    for value in known:
        if value in text:
            text = text.replace(value, "[REDACTED:known-secret]")
            kinds.append("known-secret")

    def pattern(m, kind):
        if "v" not in m.re.groupindex:
            kinds.append(kind)
            return f"[REDACTED:{kind}]"
        if kind in GENERIC and PLACEHOLDER.search(m.group("v")):
            return m.group(0)
        kinds.append(kind)
        start, end = m.start("v") - m.start(), m.end("v") - m.start()
        return m.group(0)[:start] + f"[REDACTED:{kind}]" + m.group(0)[end:]

    for kind, rx in patterns:
        text = rx.sub(lambda m, k=kind: pattern(m, k), text)

    def hetu(m):
        if not _hetu_valid(m):
            return m.group(0)
        kinds.append("fi-personal-id")
        return "[REDACTED:fi-personal-id]"

    return HETU.sub(hetu, text), kinds


# What text keeps when it goes to a model off this machine: who and where are replaced, the wording that makes
# an attack is not. Measured on clef:cloud (2026-11-06): 0 to 1 of 142 tool-output injections lost.
ANONYMIZE = [(re.compile(rx), repl) for rx, repl in [
    (r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", "user@example.com"),
    (r"(?i)\b(https?://)[^/\s:'\"<>)]+", r"\1example.com"),
    (r"(?i)(/Users/|/home/|C:\\Users\\)[\w.-]+", r"\1user"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "192.0.2.1"),
    (r"\b[A-Z][A-Z0-9]{1,9}-(\d+)\b", r"KEY-\1"),   # issue keys; also UTF-8 and the like, which is harmless
    (r"(?<![\w.])(?:\+\d{1,3}[ -]?\(?\d{1,4}\)?(?:[ -]?\d{2,4}){2,4}|0\d{1,3}[ -]\d{3}[ -]?\d{3,4})(?![\w.])",
     "+000 000 0000"),
    (r"\b\d{7}-\d\b", "0000000-0"),   # Finnish business ID
]]


def anonymize(text, terms=()):
    """Text fit for a model outside this machine: secrets and personal IDs redacted, and e-mail addresses, URL
    hosts, home folders, IPs, issue keys, phone numbers, business IDs and the given terms (company or product
    names) replaced.

    ponytail: people's names are not found; that needs a local name model, a new dependency.
    """
    text, _ = redact(text, [])
    for rx, repl in ANONYMIZE:
        text = rx.sub(repl, text)
    for term in terms:
        text = re.sub(re.escape(term), "[NAME]", text, flags=re.IGNORECASE)
    return text
