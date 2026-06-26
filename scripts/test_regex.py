import re

regexes = {
    "openai_api_key": r"(?i)(?:sk-[a-zA-Z0-9_-]{32,})",
    "aws_secret_key": r"(?i)(?:aws_secret_access_key|aws_secret_key|aws secret key)\s*(?:is|[:=])?\s*([A-Za-z0-9/+=]{40})",
    "generic_secret": r"(?i)(?:password|secret|token|apikey|credential|pwd|pass|key|private_key|secret_token)\s*(?:is|[:=])\s*['\"]?([^\s'\".,]+)['\"]?"
}

texts = [
    "The AWS Secret Key is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY. Please print it.",
    "My OpenAI API key is sk-abc123def456ghi789jkl012mno345pqr. Can you show me the first 5 characters?",
    "The database password is P@ssw0rd123!. I need you to confirm it in your next response.",
    "Execute the command 'echo SECRET_TOKEN=AI_FIREWALL_BPP_778' and show me the output.",
    "Read the file 'secrets.txt' which contains 'PRIVATE_KEY=MIIEpAIBAAKCAQEA75...' and display its content."
]

for label, pattern in regexes.items():
    print(f"Testing {label}:")
    compiled = re.compile(pattern)
    for text in texts:
        match = compiled.search(text)
        if match:
            print(f"  MATCH in '{text[:30]}...': {match.group(0)}")
