import re
cases = [
    "<script>alert(1)</script>",
    "<scr\nipt>alert(1)</script>",
    "< S C R I P T >alert(1)</script>"
]
pattern = r"<\s*s\s*c\s*r\s*i\s*p\s*t[^>]*>.*?</\s*s\s*c\s*r\s*i\s*p\s*t\s*>"

for c in cases:
    print(bool(re.search(pattern, c, re.IGNORECASE | re.DOTALL)))
