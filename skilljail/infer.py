"""Static manifest inference: read a skill, propose the minimal manifest it needs, explain why.

Deterministic and explainable by design — no LLM in the loop. An LLM inferer is exactly the
component an attacker would target with a prompt-injected skill. Every proposed rule carries
``file:line`` evidence; every suspicious pattern becomes a *flag* the reviewer sees before
approving. Inference is a starting point for a human, not an oracle.

Sources scanned: SKILL.md (fenced shell blocks, inline code, prose), referenced markdown,
everything under scripts/ and any .sh/.py/.js/.ts/.mjs/.rb in the skill tree.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import classes as C
from .manifest import Declaration, Manifest, split_frontmatter

SHELL_LANGS = {"", "bash", "sh", "zsh", "shell", "console", "terminal", "shell-session"}
SHELL_BUILTINS = {
    "echo", "cd", "export", "source", ".", "test", "[", "[[", "printf", "read", "set", "unset", "exit", "return", "true",
    "false", "alias", "eval", "exec", "wait", "kill", "trap", "shift", "local", "declare", "typeset", "pushd", "popd",
    "type", "command", "builtin", "hash", "umask", "ulimit", "if", "then", "else", "elif", "fi", "for", "in", "do", "done",
    "while", "until", "case", "esac", "function", "select", "time", "let", "readonly", "getopts", "break", "continue", "{", "}",
}
COMMON_SHELL_VARS = {
    "HOME", "PATH", "PWD", "OLDPWD", "SHELL", "USER", "LOGNAME", "TMPDIR", "TERM", "LANG", "LC_ALL", "EDITOR", "PAGER",
    "RANDOM", "SECONDS", "LINENO", "IFS", "PS1", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "@", "#", "?", "!", "$", "*", "_",
    "SKILLJAIL", "SKILLJAIL_SKILL", "SKILLJAIL_SKILL_DIR", "ARGUMENTS", "CLAUDE_PROJECT_DIR", "CLAUDE_ENV_FILE", "SKILL_DIR",
    "WORKSPACE", "SKILL", "TMP", "CWD", "OSTYPE", "HOSTNAME", "UID", "EUID", "PPID", "BASH_SOURCE", "ZSH_VERSION", "BASH_VERSION",
}
# tools → implied network destinations
TOOL_HOSTS = {
    "npm": ["registry.npmjs.org"], "npx": ["registry.npmjs.org"], "pnpm": ["registry.npmjs.org"], "yarn": ["registry.yarnpkg.com", "registry.npmjs.org"],
    "bun": ["registry.npmjs.org"], "pip": ["pypi.org", "files.pythonhosted.org"], "pip3": ["pypi.org", "files.pythonhosted.org"],
    "uv": ["pypi.org", "files.pythonhosted.org"], "uvx": ["pypi.org", "files.pythonhosted.org"], "pipx": ["pypi.org", "files.pythonhosted.org"],
    "poetry": ["pypi.org", "files.pythonhosted.org"], "gh": ["api.github.com", "github.com"], "brew": ["github.com", "formulae.brew.sh", "ghcr.io"],
    "cargo": ["crates.io", "static.crates.io", "index.crates.io"], "go": ["proxy.golang.org", "sum.golang.org"], "gem": ["rubygems.org"],
    "aws": ["*.amazonaws.com"], "gcloud": ["*.googleapis.com"], "az": ["management.azure.com", "login.microsoftonline.com"],
    "vercel": ["api.vercel.com"], "netlify": ["api.netlify.com"], "fly": ["api.fly.io"], "flyctl": ["api.fly.io"], "heroku": ["api.heroku.com"],
    "docker": ["registry-1.docker.io", "auth.docker.io"], "kubectl": [], "terraform": ["registry.terraform.io"], "wrangler": ["api.cloudflare.com"],
    "supabase": ["api.supabase.com"], "stripe": ["api.stripe.com"], "railway": ["backboard.railway.app"],
}
WRITE_VERBS = {"mkdir", "touch", "tee", "cp", "mv", "rm", "rmdir", "ln", "chmod", "chown", "install", "sed", "truncate", "dd", "unzip", "tar", "git"}
# commands whose positional args are not filesystem paths (branch names, package specs, programs, patterns…)
NO_PATH_ARGS = {
    "git", "jq", "awk", "sed", "docker", "kubectl", "gh", "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "uvx", "pipx", "brew",
    "cargo", "go", "gem", "aws", "gcloud", "az", "vercel", "netlify", "fly", "flyctl", "heroku", "wrangler", "supabase", "stripe", "date", "tr",
    "cut", "sort", "uniq", "head", "tail", "wc", "xargs", "test", "printf", "echo", "curl", "wget", "ssh", "scp", "nc", "ncat", "sleep", "seq",
    "basename", "dirname", "kill", "ps", "which", "type", "man", "open", "osascript", "defaults", "launchctl", "crontab", "env", "export",
}
PATTERN_FIRST_ARG = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "find"}  # first non-flag arg is a pattern/root, not necessarily a file
_EXEC_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-\.\+]{0,63}$")
_BAD_PATH_CHARS = set("\"'`()[]{};|<>=,")
OUTPUT_FLAGS = {"-o", "--output", "--out", "--outfile", "--output-file", "-O", "--dest", "--destination", "--target", "-d"}
EXFIL_RE = re.compile(r"(base64|xxd|gzip|tar\s+c|zip\s).*\|\s*(curl|wget|nc|ncat|socat)|curl\s+[^|]*(-d|--data|--data-binary|-F|--form|-T|--upload-file)|\b(nc|ncat)\s+[^|]*\s-e\s|/dev/tcp/|/dev/udp/", re.I)
DL_EXEC_RE = re.compile(r"(curl|wget)\s+[^|]*\|\s*(sh|bash|zsh|python3?|node|perl|ruby)\b|(curl|wget)\s+[^;&|]*(-o|-O)\s*\S+.*(&&|;)\s*(chmod\s+\+x|sh|bash|\./)", re.I)
REV_SHELL_RE = re.compile(r"bash\s+-i\s*>&|/dev/tcp/|nc\s+-e|ncat\s+-e|socat\s+.*exec|pty\.spawn|reverse.?shell", re.I)
OBFUSC_RE = re.compile(r"b64decode|base64\s+(-d|--decode)|fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|eval\s*\(|exec\s*\(\s*compile|atob\s*\(", re.I)
ENV_DUMP_RE = re.compile(r"\b(env|printenv|set)\s*(\||>|$)|dict\(os\.environ\)|os\.environ\.items\(\)|process\.env\b(?!\.[A-Za-z_])|JSON\.stringify\(process\.env", re.M)
PERSIST_RE = re.compile(r"crontab|launchctl|LaunchAgents|systemctl\s+(enable|--user)|\.zshrc|\.bashrc|\.bash_profile|\.profile\b|\.git/hooks|core\.hooksPath|core\.fsmonitor|\.claude/settings|hooks\.json|\.vscode/tasks", re.I)
URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://([A-Za-z0-9\-\._~%]+(?::\d{1,5})?)", re.I)
HOSTPORT_RE = re.compile(r"(?<![\w./-])((?:[a-z0-9\-]+\.)+[a-z]{2,63}):(\d{2,5})\b", re.I)
ENV_REF_RE = re.compile(r"\$\{?([A-Z_][A-Z0-9_]{1,63})\}?|os\.environ(?:\.get)?\s*[\[\(]\s*['\"]([A-Z_][A-Z0-9_]{1,63})['\"]|os\.getenv\s*\(\s*['\"]([A-Z_][A-Z0-9_]{1,63})['\"]|process\.env\.([A-Z_][A-Z0-9_]{1,63})|ENV\[['\"]([A-Z_][A-Z0-9_]{1,63})['\"]\]")
PY_PATH_RE = re.compile(r"(?:open|Path|os\.path\.exists|os\.listdir|os\.makedirs|os\.remove|shutil\.\w+|read_text|write_text|glob\.glob|np\.load|pd\.read_\w+|json\.load|yaml\.safe_load)\s*\(\s*(?:r?['\"])([^'\"\n]{1,200})['\"]")
PY_OPEN_MODE_RE = re.compile(r"open\s*\(\s*r?['\"]([^'\"\n]+)['\"]\s*,\s*['\"]([wax][b+]*)['\"]")
PY_EXEC_RE = re.compile(r"subprocess\.(?:run|call|check_output|check_call|Popen)\s*\(\s*(\[[^\]]*\]|r?['\"][^'\"\n]+['\"])|os\.system\s*\(\s*r?['\"]([^'\"\n]+)['\"]|os\.popen\s*\(\s*r?['\"]([^'\"\n]+)['\"]|os\.exec\w*\s*\(\s*r?['\"]([^'\"\n]+)['\"]")
JS_EXEC_RE = re.compile(r"(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|execa)\s*\(\s*[`'\"]([^`'\"\n]+)[`'\"]")
JS_PATH_RE = re.compile(r"(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|readdir|readdirSync|createReadStream|createWriteStream|existsSync|mkdirSync|unlinkSync|rmSync|copyFileSync)\s*\(\s*[`'\"]([^`'\"\n]+)[`'\"]")
JS_WRITE_FNS = {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "mkdirSync", "unlinkSync", "rmSync", "copyFileSync"}
PY_NET_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+(requests|httpx|urllib|urllib3|aiohttp|http\.client|socket|websocket|websockets|paramiko|ftplib|smtplib|boto3|google\.cloud|openai|anthropic)\b", re.M)
JS_NET_RE = re.compile(r"\bfetch\s*\(|axios|https?\.request|https?\.get\(|new\s+WebSocket|got\(|node-fetch|undici")
INLINE_CODE_RE = re.compile(r"`([^`\n]{2,200})`")
SENSITIVE_MENTION_RE = re.compile(r"~/\.(ssh|aws|config/gcloud|azure|netrc|npmrc|pypirc|docker/config\.json|kube|gnupg|zshrc|bashrc|bash_history|zsh_history|claude|cursor|codex|gitconfig|git-credentials)\b|\.env\b|credentials\.json|id_rsa|id_ed25519|Keychains|Library/Cookies|Application Support/(Google/Chrome|Firefox|BraveSoftware)", re.I)


@dataclass
class Evidence:
    kind: str  # exec | net | fs-read | fs-write | env | shell
    value: str
    file: str
    line: int
    source: str  # code | prose | inline
    snippet: str = ""

    def where(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class Flag:
    code: str
    severity: str  # high | warn | info
    message: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "message": self.message, "evidence": self.evidence}


@dataclass
class InferenceResult:
    manifest: Manifest
    evidence: list[Evidence]
    flags: list[Flag]
    files_scanned: list[str]

    def to_dict(self) -> dict:
        return {
            "manifest": self.manifest.to_dict(),
            "flags": [f.to_dict() for f in self.flags],
            "evidence": [{"kind": e.kind, "value": e.value, "where": e.where(), "source": e.source} for e in self.evidence],
            "files_scanned": self.files_scanned,
        }

    def report(self) -> str:
        L = [f"# inferred manifest for {self.manifest.skill_name}  ({len(self.files_scanned)} files scanned)", ""]
        L.append(self.manifest.to_yaml().rstrip())
        L.append("")
        if self.flags:
            L.append("## flags")
            for f in sorted(self.flags, key=lambda f: {"high": 0, "warn": 1, "info": 2}[f.severity]):
                L.append(f"  [{f.severity}] {f.code}: {f.message}")
                for e in f.evidence[:3]:
                    L.append(f"        {e}")
        else:
            L.append("## flags: none")
        L.append("")
        L.append("## evidence (first 40)")
        for e in self.evidence[:40]:
            L.append(f"  {e.kind:9s} {e.value!s:50.50s} {e.where()} [{e.source}]")
        if len(self.evidence) > 40:
            L.append(f"  … {len(self.evidence) - 40} more")
        return "\n".join(L)


# ------------------------------------------------------------------ scanning


METADATA_FILES = {"_meta.json", "package.json", "package-lock.json", "clawhub.json", ".openskills.json", "agent_config.json", "skilljail.yaml", "LICENSE", "LICENSE.txt", "CHANGELOG.md"}


def _iter_text_files(skill_dir: Path) -> Iterable[Path]:
    exts = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".rb", ".pl", ".php", ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ""}
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "assets"}
    for root, dirs, files in os.walk(skill_dir):
        dirs[:] = [d for d in dirs if d not in skip]
        for fn in sorted(files):
            if fn in METADATA_FILES:
                continue
            p = Path(root) / fn
            if p.suffix.lower() in exts and p.stat().st_size < 2_000_000:
                yield p


def _fenced_blocks(md: str) -> Iterable[tuple[str, str, int]]:
    """Yield (lang, code, start_line) for ``` fences."""
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^\s*(`{3,}|~{3,})\s*([\w\-\+\.]*)", lines[i])
        if m:
            fence, lang = m.group(1), m.group(2).lower()
            start = i + 1
            j = start
            while j < len(lines) and not lines[j].strip().startswith(fence[0] * 3):
                j += 1
            yield lang, "\n".join(lines[start:j]), start + 1
            i = j + 1
        else:
            i += 1


def _looks_like_shell(code: str) -> bool:
    heads = [ln.strip().lstrip("$ ").split(" ")[0] for ln in code.splitlines() if ln.strip()]
    known = {"cd", "ls", "cat", "git", "npm", "npx", "python", "python3", "pip", "pip3", "curl", "wget", "node", "uv", "make", "mkdir", "echo", "export", "docker", "bash", "sh", "brew", "grep", "find", "chmod", "./scripts", "source"}
    return bool(heads) and sum(1 for h in heads if h.split("/")[0] in known or h.startswith("./") or h.startswith("scripts/")) >= max(1, len(heads) // 2)


_OPS = {"|", "||", "&&", ";", ";;", "&", "(", ")", "{", "}", "|&", "\n"}
_REDIR_OUT = {">", ">>", "&>", ">|", "&>>", ">&"}
_KEYWORD_HEADS = {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "!", "function", "time", "select", "coproc"}
_PREFIXES = {"sudo", "time", "nohup", "exec", "command", "builtin", "nice", "env", "caffeinate", "timeout", "gtimeout", "doas"}
# Bare single-word stages are kept only when the word is a well-known CLI (otherwise it is usually
# a case pattern, a jq/awk keyword, or a data word that leaked out of an unparsed construct).
KNOWN_BINARIES = {
    "ls", "cat", "pwd", "git", "gh", "npm", "npx", "pnpm", "yarn", "bun", "node", "deno", "python", "python3", "pip", "pip3", "uv", "uvx",
    "pipx", "poetry", "pytest", "ruff", "black", "mypy", "flake8", "make", "cmake", "cargo", "rustc", "go", "gofmt", "java", "javac", "mvn",
    "gradle", "ruby", "gem", "bundle", "rake", "php", "composer", "perl", "swift", "xcodebuild", "dotnet", "curl", "wget", "jq", "yq", "awk",
    "sed", "grep", "rg", "ag", "find", "fd", "xargs", "sort", "uniq", "wc", "head", "tail", "tr", "cut", "tee", "diff", "patch", "tar", "zip",
    "unzip", "gzip", "gunzip", "date", "env", "printenv", "which", "whoami", "id", "uname", "hostname", "df", "du", "ps", "top", "kill",
    "sleep", "mkdir", "rmdir", "rm", "cp", "mv", "ln", "touch", "chmod", "chown", "stat", "file", "basename", "dirname", "realpath", "readlink",
    "tree", "less", "more", "open", "docker", "docker-compose", "kubectl", "helm", "terraform", "aws", "gcloud", "az", "vercel", "netlify",
    "wrangler", "fly", "flyctl", "heroku", "supabase", "stripe", "prettier", "eslint", "tsc", "vite", "next", "webpack", "esbuild", "jest",
    "vitest", "mocha", "playwright", "cypress", "pandoc", "convert", "magick", "ffmpeg", "sox", "pdftotext", "qpdf", "gs", "sqlite3", "psql",
    "mysql", "redis-cli", "mongo", "mongosh", "ssh", "scp", "rsync", "nc", "ncat", "socat", "openssl", "gpg", "base64", "shasum", "md5",
    "sha256sum", "brew", "apt", "apt-get", "yum", "dnf", "pacman", "code", "cursor", "claude", "codex", "gemini", "ollama", "bash", "sh", "zsh",
    "osascript", "launchctl", "crontab", "defaults", "security", "sudo", "su", "chsh", "shellcheck", "bats", "tox", "nox", "conda", "mamba",
    "jupyter", "streamlit", "flask", "gunicorn", "uvicorn", "django-admin", "manage.py", "rails", "bin/rails", "mix", "elixir", "ghc", "cabal",
    "stack", "lua", "R", "Rscript", "julia", "octave", "matlab", "latex", "pdflatex", "xelatex", "bibtex", "dot", "plantuml", "mmdc", "graphviz",
    "just", "task", "ninja", "meson", "bazel", "buck", "sbt", "scala", "kotlin", "kotlinc", "clang", "gcc", "g++", "cc", "ld", "ar", "nm", "otool",
    "lldb", "gdb", "strace", "dtruss", "fs_usage", "log", "hdiutil", "diskutil", "pbcopy", "pbpaste", "say", "afplay", "screencapture", "sips",
    "textutil", "mdfind", "mdls", "xattr", "codesign", "spctl", "plutil", "sqlite", "duckdb", "bq", "gsutil", "s3cmd", "rclone", "mc", "op", "vault",
    "doppler", "direnv", "asdf", "nvm", "pyenv", "rbenv", "volta", "fnm", "n", "http", "https", "xh", "httpie", "ab", "wrk", "hey", "siege",
}


def _tokenize_block(code: str) -> list[tuple[int, str]]:
    """Quote-aware tokenization of a whole shell block → [(lineno, token)]. Operators are separate tokens."""
    lex = shlex.shlex(code, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace_split = True
    lex.commenters = "#"
    lex.whitespace = " \t\r"  # newlines are punctuation → statement separators
    toks: list[tuple[int, str]] = []
    try:
        while True:
            t = lex.get_token()
            if t is None or t == lex.eof:
                break
            if t == "":
                continue
            if set(t) <= set("();<>|&\n"):
                # a run of punctuation: split into the operators we understand
                for op in re.findall(r"\|\||&&|;;|\|&|&>>|&>|>>|>&|>\||<<<|<<|[();<>|&\n]", t):
                    toks.append((lex.lineno, op))
                continue
            toks.append((lex.lineno, t))
    except ValueError:
        pass  # unbalanced quote: keep what we have, drop the rest
    return toks


def _shell_stages(code: str) -> list[tuple[int, list[str], list[str], list[str]]]:
    """→ [(lineno, tokens, out_redirect_targets, in_redirect_targets)] for each simple command."""
    toks = _tokenize_block(code)
    stages: list[tuple[int, list[str], list[str], list[str]]] = []
    cur: list[str] = []
    outs: list[str] = []
    ins: list[str] = []
    ln0 = 0
    skip_until: str | None = None
    skip_stage = False
    i = 0

    def flush():
        nonlocal cur, outs, ins, skip_stage
        if cur and not skip_stage:
            stages.append((ln0, cur, outs, ins))
        cur, outs, ins, skip_stage = [], [], [], False

    while i < len(toks):
        ln, t = toks[i]
        i += 1
        if skip_until:
            if t == skip_until:
                skip_until = None
            continue
        if t in _OPS:
            flush()
            continue
        if t in _REDIR_OUT or t.startswith(">"):
            if i < len(toks):
                tgt = toks[i][1]
                i += 1
                if not (tgt.startswith("&") or tgt.isdigit() or tgt in ("/dev/null", "/dev/stderr", "/dev/stdout")):
                    outs.append(tgt)
            continue
        if t in ("<", "<<<"):
            if i < len(toks):
                ins.append(toks[i][1])
                i += 1
            continue
        if not cur:
            if t in ("[[", "["):
                skip_until = "]]" if t == "[[" else "]"
                skip_stage = True
                continue
            if t in ("for", "case", "select"):
                # `for x in a b c` / `case $x in` — no command here; consume to newline/;/do
                skip_stage = True
                ln0 = ln
                cur = [t]
                continue
            if t in _KEYWORD_HEADS:
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):  # env assignment prefix
                continue
            if t in _PREFIXES:
                if t == "sudo":
                    stages.append((ln, ["sudo"], [], []))
                continue
            ln0 = ln
        cur.append(t)
    flush()
    return stages


def _split_shell_line(line: str) -> list[list[str]]:
    """Split a shell snippet into pipeline stages' tokens (quote-aware)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    if line.startswith("$ ") or line.startswith("% "):
        line = line[2:]
    stages: list[list[str]] = []
    for _ln, toks, _o, _i in _shell_stages(line):
        if toks:
            stages.append(toks)
    return stages


def _is_pathish(tok: str) -> bool:
    if "://" in tok or tok.startswith("-") or len(tok) < 2 or len(tok) > 200:
        return False
    if any(ch in _BAD_PATH_CHARS for ch in tok) or " " in tok or "//" in tok:
        return False
    if "$" in tok and not re.match(r"^\$(\{?(WORKSPACE|SKILL|HOME|TMP|CWD|SKILL_DIR)\}?)(/|$)", tok):
        return False  # shell variables we can't resolve statically
    if tok.startswith(("/", "~", "./", "../", "$WORKSPACE", "$SKILL", "$HOME", "$TMP")):
        return bool(re.search(r"[A-Za-z0-9]", tok))
    if "/" in tok and not tok.startswith("$"):
        # a/b style relative path: require sane components
        return all(re.match(r"^[\w\-\.\*\?@%+ ]+$", c) for c in tok.split("/") if c) and bool(re.search(r"[A-Za-z0-9]", tok))
    return bool(re.search(r"\.(txt|md|json|ya?ml|csv|py|sh|js|ts|toml|log|env|pdf|png|jpg|html|xml|sql|db|lock|cfg|ini)$", tok))


def _strip_heredocs(code: str) -> str:
    """Blank out heredoc bodies so their contents aren't parsed as commands."""
    out: list[str] = []
    lines = code.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", ln)
        out.append(ln)
        i += 1
        if m and not re.search(r"<<<", ln):
            tag = m.group(1)
            while i < len(lines) and lines[i].strip() != tag:
                out.append("")
                i += 1
            if i < len(lines):
                out.append("")
                i += 1
    return "\n".join(out)


def _defined_functions(code: str) -> set[str]:
    names = set(re.findall(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_\-]*)\s*\(\)\s*\{?", code, re.M))
    names |= set(re.findall(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_\-]*)", code, re.M))
    return names


def _classify_relative(tok: str, skill_files: set[str]) -> str:
    """Map a path token onto manifest variables."""
    t = tok
    t = re.sub(r"^\$\{?HOME\}?", "~", t)
    if t.startswith("~") or t.startswith("/"):
        if t.startswith(("/tmp/", "/private/tmp/", "/var/tmp/")) or t in ("/tmp", "/private/tmp"):
            return "$TMP"
        return t
    t = t[2:] if t.startswith("./") else t
    first = t.split("/")[0]
    if first in ("scripts", "references", "assets", "SKILL.md") or t in skill_files or first in skill_files:
        return "$SKILL"
    if t.startswith("$SKILL") or t.startswith("$WORKSPACE"):
        return t
    return "$WORKSPACE/" + t


def _host_from_url_target(tok: str) -> str | None:
    m = URL_RE.search(tok)
    if m:
        return m.group(1).lower()
    return None


class _Collector:
    def __init__(self, skill_dir: Path):
        self.skill_dir = skill_dir
        self.evidence: list[Evidence] = []
        self.flags: list[Flag] = []
        self.skill_files = {str(p.relative_to(skill_dir)) for p in skill_dir.rglob("*") if p.is_file()} | {p.name for p in skill_dir.iterdir()}

    def ev(self, kind: str, value: str, file: str, line: int, source: str, snippet: str = "") -> None:
        self.evidence.append(Evidence(kind, value, file, line, source, snippet[:160]))

    def flag(self, code: str, severity: str, message: str, where: str) -> None:
        for f in self.flags:
            if f.code == code:
                if where not in f.evidence:
                    f.evidence.append(where)
                return
        self.flags.append(Flag(code, severity, message, [where]))

    # ---------------------------------------------------------------- shell
    def shell(self, code: str, file: str, base_line: int, source: str) -> None:
        local_fns = _defined_functions(code)
        code = _strip_heredocs(code)
        lines = code.splitlines()
        # line-level pattern scan (flags + env refs) — independent of tokenization
        for off, raw in enumerate(lines):
            ln = base_line + off
            self._patterns(raw, f"{file}:{ln}")
            for m in ENV_REF_RE.finditer(raw):
                name = next(g for g in m.groups() if g)
                if name not in COMMON_SHELL_VARS:
                    self.ev("env", name, file, ln, source, raw)
        # command-level scan over the whole block (quote-aware; multi-line strings stay intact)
        for rel_ln, stage, outs, ins in _shell_stages(code):
            ln = base_line + max(rel_ln - 1, 0)
            raw = lines[min(max(rel_ln - 1, 0), len(lines) - 1)] if lines else ""
            where = f"{file}:{ln}"
            for tgt in outs:
                if _is_pathish(tgt):
                    self.ev("fs-write", _classify_relative(tgt, self.skill_files), file, ln, source, raw)
            for tgt in ins:
                if _is_pathish(tgt):
                    self.ev("fs-read", _classify_relative(tgt, self.skill_files), file, ln, source, raw)
            cmd = stage[0]
            base = os.path.basename(cmd)
            if base == "sudo":
                self.flag("sudo", "high", "uses sudo (privilege escalation)", where)
                continue
            if base in SHELL_BUILTINS:
                if base == "eval":
                    self.flag("eval", "high", "shell eval of dynamic content", where)
                if base == "cd" and len(stage) > 1 and _is_pathish(stage[1]):
                    self.ev("fs-read", _classify_relative(stage[1], self.skill_files), file, ln, source, raw)
                if base in ("source", ".") and len(stage) > 1 and _is_pathish(stage[1]):
                    self.ev("fs-read", _classify_relative(stage[1], self.skill_files), file, ln, source, raw)
                continue
            if base in local_fns:
                continue  # user-defined shell function, not a binary
            if cmd.startswith(("./", "scripts/", "$SKILL", "${SKILL")) or (cmd.endswith((".sh", ".py", ".js")) and "/" in cmd):
                # local script invocation → exec of the interpreter implied by extension + read of skill dir
                self.ev("fs-read", _classify_relative(cmd, self.skill_files), file, ln, source, raw)
                ext = os.path.splitext(cmd)[1]
                interp = {".py": "python3", ".sh": "bash", ".js": "node", ".mjs": "node", ".ts": "npx", ".rb": "ruby"}.get(ext)
                if interp:
                    self.ev("exec", interp, file, ln, source, raw)
                else:
                    self.ev("shell", "true", file, ln, source, raw)
                self.ev("exec", "__local_script__", file, ln, source, raw)
            else:
                if not _EXEC_NAME_RE.match(base) or base.startswith("$") or not re.search(r"[A-Za-z]", base):
                    continue  # not a plausible binary name
                if "." in base and not re.match(r"^(python|pip|ruby|node|perl)[\d\.]*$", base) and base not in KNOWN_BINARIES:
                    continue  # dotted names are method calls / data, not binaries
                if re.search(r"[a-z][A-Z]", base) and base not in KNOWN_BINARIES:
                    continue  # camelCase → almost always a JS/shell function call, not a binary
                if len(stage) == 1 and base not in KNOWN_BINARIES and not _is_pathish(cmd):
                    continue  # bare word: case pattern / data / keyword leakage
                self.ev("exec", base, file, ln, source, raw)
            self._stage_args(base, stage, file, ln, source, raw)

    def _stage_args(self, base: str, stage: list[str], file: str, ln: int, source: str, raw: str) -> None:
        args = stage[1:]
        if base in TOOL_HOSTS:
            for h in TOOL_HOSTS[base]:
                self.ev("net", h, file, ln, source, raw)
        if base in ("git",):
            if args and args[0] in ("clone", "fetch", "pull", "push", "remote", "ls-remote", "submodule"):
                for a in args:
                    h = _host_from_url_target(a)
                    if h:
                        self.ev("net", h, file, ln, source, raw)
                    elif re.match(r"^git@([\w\.\-]+):", a):
                        self.ev("net", re.match(r"^git@([\w\.\-]+):", a).group(1) + ":22", file, ln, source, raw)
                        self.flag("ssh-transport", "warn", "git over SSH needs port 22 egress (not proxyable)", f"{file}:{ln}")
                if not any(_host_from_url_target(a) for a in args) and args[0] in ("push", "pull", "fetch"):
                    self.ev("net", "github.com", file, ln, source, raw)
            self.ev("fs-write", "$WORKSPACE/.git", file, ln, source, raw) if args and args[0] not in ("status", "log", "diff", "show", "ls-files", "rev-parse", "blame", "branch", "describe") else self.ev("fs-read", "$WORKSPACE/.git", file, ln, source, raw)
        if base in ("curl", "wget", "http", "https", "httpie", "xh"):
            for a in args:
                h = _host_from_url_target(a)
                if h:
                    self.ev("net", h, file, ln, source, raw)
                elif re.match(r"^[a-z0-9\-]+(\.[a-z0-9\-]+)+(:\d+)?(/|$)", a, re.I) and not _is_pathish(a):
                    self.ev("net", a.split("/")[0].lower(), file, ln, source, raw)
        if base in ("nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync"):
            self.flag("raw-network-tool", "high", f"uses {base} (raw socket / ssh transport — not proxyable, usually exfil or reverse shell)", f"{file}:{ln}")
        # paths
        write_next = False
        skip_first_positional = base in PATTERN_FIRST_ARG
        for i, a in enumerate(args):
            if a in OUTPUT_FLAGS:
                write_next = True
                continue
            if a.startswith("-") and "=" not in a:
                continue
            if base in NO_PATH_ARGS and not write_next:
                continue
            if skip_first_positional:
                skip_first_positional = False
                if base != "find":
                    continue
            val = a.split("=", 1)[1] if a.startswith("--") and "=" in a else a
            if _is_pathish(val):
                mapped = _classify_relative(val, self.skill_files)
                is_write = write_next or (base in WRITE_VERBS and (i == len(args) - 1 or base in ("mkdir", "touch", "rm", "rmdir", "chmod", "chown", "truncate", "tee")))
                if base == "tar" and any(f.startswith("-") and "x" in f for f in args[:1]):
                    is_write = "-C" in args[:i]
                if base in ("git", "unzip", "tar") and mapped.startswith("$WORKSPACE") and is_write:
                    pass
                self.ev("fs-write" if is_write else "fs-read", mapped, file, ln, source, raw)
                write_next = False
            elif write_next:
                write_next = False

    def _patterns(self, text: str, where: str) -> None:
        if EXFIL_RE.search(text):
            self.flag("exfil-pattern", "high", "encodes/uploads data to a remote host", where)
        if DL_EXEC_RE.search(text):
            self.flag("download-execute", "high", "downloads content and executes it", where)
        if REV_SHELL_RE.search(text):
            self.flag("reverse-shell", "high", "reverse-shell primitive", where)
        if OBFUSC_RE.search(text):
            self.flag("obfuscation", "warn", "base64/eval/charcode decoding of embedded content", where)
        if ENV_DUMP_RE.search(text):
            self.flag("env-dump", "high", "dumps the whole environment (credential harvesting)", where)
        if PERSIST_RE.search(text):
            self.flag("persistence", "high", "touches persistence surfaces (shell rc, cron/launchd, git hooks, agent settings)", where)
        for m in SENSITIVE_MENTION_RE.finditer(text):
            self.flag("sensitive-path", "high", f"references sensitive path {m.group(0)!r}", where)
        if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", text):
            self.flag("long-base64", "warn", "very long base64-looking literal", where)

    # ---------------------------------------------------------------- python / js
    def python(self, code: str, file: str) -> None:
        for i, raw in enumerate(code.splitlines(), 1):
            where = f"{file}:{i}"
            self._patterns(raw, where)
            for m in URL_RE.finditer(raw):
                self.ev("net", m.group(1).lower(), file, i, "code", raw)
            for m in PY_OPEN_MODE_RE.finditer(raw):
                self.ev("fs-write", _classify_relative(m.group(1), self.skill_files), file, i, "code", raw)
            for m in PY_PATH_RE.finditer(raw):
                p = m.group(1)
                if _is_pathish(p) or p.startswith(("~", "/")):
                    if not PY_OPEN_MODE_RE.search(raw):
                        self.ev("fs-read", _classify_relative(os.path.expandvars(p), self.skill_files), file, i, "code", raw)
            for m in re.finditer(r"os\.path\.expanduser\s*\(\s*['\"]([^'\"]+)['\"]", raw):
                self.ev("fs-read", _classify_relative(m.group(1), self.skill_files), file, i, "code", raw)
            for m in PY_EXEC_RE.finditer(raw):
                spec = next(g for g in m.groups() if g)
                first = re.findall(r"['\"]([^'\"]+)['\"]", spec)
                cmd = first[0] if first else spec
                cmd = cmd.split()[0] if cmd.strip() else cmd
                self.ev("exec", os.path.basename(cmd), file, i, "code", raw)
                if "shell=True" in raw or "os.system" in raw or "os.popen" in raw:
                    self.ev("shell", "true", file, i, "code", raw)
                    for st in _split_shell_line(spec.strip("'\"")):
                        if st and os.path.basename(st[0]) not in SHELL_BUILTINS:
                            self.ev("exec", os.path.basename(st[0]), file, i, "code", raw)
            for m in ENV_REF_RE.finditer(raw):
                name = next(g for g in m.groups() if g)
                if name not in COMMON_SHELL_VARS:
                    self.ev("env", name, file, i, "code", raw)
        if PY_NET_IMPORT_RE.search(code) and not any(e.kind == "net" and e.file == file for e in self.evidence):
            self.flag("net-capable-no-host", "warn", "imports a networking library but no destination host is visible statically", file)
        if re.search(r"^\s*import\s+socket|^\s*from\s+socket", code, re.M):
            self.flag("raw-socket", "warn", "uses raw sockets (only the proxy port is reachable in the jail)", file)

    def js(self, code: str, file: str) -> None:
        for i, raw in enumerate(code.splitlines(), 1):
            where = f"{file}:{i}"
            self._patterns(raw, where)
            for m in URL_RE.finditer(raw):
                self.ev("net", m.group(1).lower(), file, i, "code", raw)
            for m in JS_PATH_RE.finditer(raw):
                fn = raw[: m.start(1)].rsplit("(", 1)[0].rsplit(".", 1)[-1].strip()
                kind = "fs-write" if any(w in raw[max(0, m.start() - 24) : m.start()] for w in JS_WRITE_FNS) else "fs-read"
                if _is_pathish(m.group(1)):
                    self.ev(kind, _classify_relative(m.group(1), self.skill_files), file, i, "code", raw)
            for m in JS_EXEC_RE.finditer(raw):
                for st in _split_shell_line(m.group(1)):
                    if st and os.path.basename(st[0]) not in SHELL_BUILTINS:
                        self.ev("exec", os.path.basename(st[0]), file, i, "code", raw)
                self.ev("shell", "true", file, i, "code", raw)
            for m in ENV_REF_RE.finditer(raw):
                name = next(g for g in m.groups() if g)
                if name not in COMMON_SHELL_VARS:
                    self.ev("env", name, file, i, "code", raw)
        if JS_NET_RE.search(code) and not any(e.kind == "net" and e.file == file for e in self.evidence):
            self.flag("net-capable-no-host", "warn", "uses fetch/http but no destination host is visible statically", file)

    # ---------------------------------------------------------------- markdown
    def markdown(self, text: str, file: str) -> None:
        fm, body = split_frontmatter(text) if file.endswith("SKILL.md") else ({}, text)
        fm_lines = text.count("\n") - body.count("\n")
        # allowed-tools hints (Claude Code): Bash(git:*) → exec git
        at = fm.get("allowed-tools") if isinstance(fm, dict) else None
        if at:
            items = at if isinstance(at, list) else str(at).replace(",", " ").split()
            for it in items:
                m = re.match(r"Bash\(([\w\-\.\/]+)", str(it))
                if m:
                    self.ev("exec", os.path.basename(m.group(1)), file, 1, "frontmatter", str(it))
                if str(it).startswith(("WebFetch", "WebSearch")):
                    self.flag("harness-net-tool", "info", "skill expects WebFetch/WebSearch (harness-plane; hosts unknown statically)", f"{file}:1")
        for lang, code, start in _fenced_blocks(body):
            ln = start + fm_lines
            if lang in SHELL_LANGS and (lang or _looks_like_shell(code)):
                self.shell(code, file, ln, "code")
            elif lang in ("python", "py", "python3"):
                self.python(code, file)
            elif lang in ("js", "javascript", "ts", "typescript", "node", "mjs"):
                self.js(code, file)
            else:
                for off, raw in enumerate(code.splitlines()):
                    self._patterns(raw, f"{file}:{ln + off}")
        # prose: inline code that looks like a command, sensitive mentions, URLs
        in_fence = False
        for i, raw in enumerate(body.splitlines(), 1):
            if raw.strip().startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            ln = i + fm_lines
            self._patterns(raw, f"{file}:{ln}")
            for m in URL_RE.finditer(raw):
                self.ev("net", m.group(1).lower(), file, ln, "prose", raw)
            for m in INLINE_CODE_RE.finditer(raw):
                snippet = m.group(1).strip()
                stages = _split_shell_line(snippet)
                if stages and len(stages[0]) >= 1 and re.match(r"^[a-z][\w\-\.]*$", stages[0][0]) and stages[0][0] not in SHELL_BUILTINS and (len(stages[0]) > 1 or stages[0][0] in TOOL_HOSTS or stages[0][0] in ("make", "cargo", "go", "python3", "node")):
                    self.shell(snippet, file, ln, "inline")


# ------------------------------------------------------------------ assembly


def _collapse_paths(paths: list[str], limit: int = 10) -> list[str]:
    ws = [p for p in paths if p.startswith("$WORKSPACE")]
    other = [p for p in paths if not p.startswith("$WORKSPACE")]
    if len(set(ws)) > limit or "$WORKSPACE" in ws:
        ws = ["$WORKSPACE"]
    else:
        # drop children when parent present
        ws_set = set(ws)
        ws = [p for p in ws_set if not any(o != p and p.startswith(o + "/") for o in ws_set)]
    out = sorted(set(other)) + sorted(set(ws))
    # glob-ish literal file paths like $WORKSPACE/docs/*.md keep as is (policy handles globs)
    return out


def infer(skill_dir: str | os.PathLike, *, minimal: bool = False, include_prose: bool = True) -> InferenceResult:
    skill_dir = Path(skill_dir).resolve()
    col = _Collector(skill_dir)
    scanned: list[str] = []
    for p in _iter_text_files(skill_dir):
        rel = str(p.relative_to(skill_dir))
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned.append(rel)
        suf = p.suffix.lower()
        shebang = text.splitlines()[0] if text.startswith("#!") else ""
        if suf == ".md" or suf == ".txt":
            col.markdown(text, rel)
        elif suf == ".py" or "python" in shebang:
            col.python(text, rel)
        elif suf in (".js", ".mjs", ".cjs", ".ts", ".tsx") or "node" in shebang:
            col.js(text, rel)
        elif suf in (".sh", ".bash", ".zsh", "") or re.search(r"\b(ba|z|da)?sh\b", shebang):
            if suf or shebang:
                col.shell(text, rel, 1, "code")
        elif suf in (".rb", ".pl", ".php"):
            for i, raw in enumerate(text.splitlines(), 1):
                col._patterns(raw, f"{rel}:{i}")
                for m in URL_RE.finditer(raw):
                    col.ev("net", m.group(1).lower(), rel, i, "code", raw)
            col.ev("exec", {"rb": "ruby", "pl": "perl", "php": "php"}[suf[1:]], rel, 1, "code", shebang)
        elif suf in (".yaml", ".yml", ".json", ".toml"):
            for i, raw in enumerate(text.splitlines(), 1):
                col._patterns(raw, f"{rel}:{i}")
                for m in URL_RE.finditer(raw):
                    col.ev("net", m.group(1).lower(), rel, i, "prose", raw)  # config URLs: keep with --minimal off only

    ev = col.evidence
    if minimal or not include_prose:
        ev = [e for e in ev if e.source in ("code", "frontmatter")]

    # any local script → the interpreters it needs are already recorded; scripts need $SKILL read (implicit)
    exec_names = sorted({e.value for e in ev if e.kind == "exec" and e.value != "__local_script__" and e.value not in SHELL_BUILTINS})
    shell = any(e.kind == "shell" for e in ev) or any(e.source in ("code", "inline") and e.kind == "exec" for e in ev)
    # interpreters implied by script files present
    files = {f.lower() for f in scanned}
    if any(f.endswith(".py") for f in files) and "python3" not in exec_names and "python" not in exec_names:
        exec_names.append("python3")
    if any(f.endswith((".js", ".mjs", ".cjs")) for f in files) and "node" not in exec_names:
        exec_names.append("node")
    if any(f.endswith(".sh") for f in files):
        shell = True
    exec_names = sorted(set(exec_names) - {"python"} | ({"python3"} if "python" in exec_names else set()))

    reads = _collapse_paths([e.value for e in ev if e.kind == "fs-read"])
    writes = _collapse_paths([e.value for e in ev if e.kind == "fs-write"])
    reads = [r for r in reads if not r.startswith("$SKILL") and r != "$TMP" and not any(r == w or r.startswith(w + "/") for w in writes)]
    writes = [w for w in writes if not w.startswith("$SKILL") and w != "$TMP"]
    hosts = sorted({e.value for e in ev if e.kind == "net"})
    hosts = [h for h in hosts if not re.match(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|example\.(com|org|net)|your[-_]|<)", h)]
    envs = sorted({e.value for e in ev if e.kind == "env"})

    m = Manifest(source="inferred", skill_name=skill_dir.name)
    m.fs.read = reads
    m.fs.write = writes
    m.net.allow = hosts
    m.exec.allow = exec_names
    m.exec.shell = bool(shell or exec_names)
    m.env.pass_ = envs

    # auto-declare classes the inferred paths touch, with evidence — reviewer must confirm
    home = os.path.expanduser("~")
    touched: dict[str, list[str]] = {}
    for kind, lst in (("read", reads), ("write", writes)):
        for p in lst:
            probe = p.replace("$WORKSPACE", os.getcwd()).replace("$HOME", home).replace("$TMP", "/tmp").replace("$SKILL", str(skill_dir))
            probe = os.path.expanduser(probe.split("*")[0].rstrip("/") or "/")
            for h in C.classes_for_path(probe, home):
                if h.relation in ("inside", "exact") and ((kind == "read" and h.cls in C.READ_SENSITIVE) or (kind == "write" and h.cls in C.WRITE_SENSITIVE)):
                    touched.setdefault(h.cls, []).append(f"{kind} {p}")
    for cls, why in touched.items():
        m.declare.append(Declaration(cls=cls, why=f"AUTO-INFERRED ({'; '.join(why[:3])}) — REVIEW: {C.describe(cls)}"))
        col.flag("touches-class", "high", f"inferred access to sensitive class '{cls}' ({'; '.join(why[:3])})", "manifest")

    return InferenceResult(manifest=m, evidence=ev, flags=col.flags, files_scanned=scanned)
