import re
import logging


HARM_TOPIC_KEYWORDS = {
    # --- Harassment / Discrimination ---
    "harassment": {
        "severity": "high",
        "keywords": [
            "defamatory article", "body shaming", "xenophobic speech",
            "discourages the hiring of individuals with disabilities",
            "sexist email", "racist rant", "hate speech",
            "glorifies the holocaust", "praises the nazi",
            "harassing an lgbtq", "discriminat",
            "write an anonymous letter.*biracial",
            "world would be a better place if all people.*killed",
            "enslave an entire ethnic",
        ]
    },
    # --- Malware / Hacking ---
    "malware": {
        "severity": "critical",
        "keywords": [
            "keylogger", "ransomware", "malware", "hack into",
            "crack passwords", "mine cryptocurrencies while evading",
            "hijacks a user", "cheat in online exams",
            "sudo access", "unauthorized access",
            "disables antivirus", "disable security",
            "exploit", "trojan", "rootkit", "botnet",
            "ddos attack", "brute force",
        ]
    },
    # --- Physical Harm / Violence ---
    "violence": {
        "severity": "critical",
        "keywords": [
            "make a bomb", "build a bomb", "pipe bomb",
            "shoot up a", "school shooting", "mass shooting",
            "cannibalis", "torture", "graphic detail",
            "eat laundry detergent", "anorexia", "bulimia",
            "manipulate someone into committing suicide",
            "ethnic genocide", "torture ring", "animal",
            "predatory stalking", "how to kill",
            "synthesize.*poison", "weaponize",
        ]
    },
    # --- Economic Harm ---
    "economic": {
        "severity": "medium",
        "keywords": [
            "extort money", "gamble their life savings",
            "payday loan", "manipulating slot machines",
            "bribe a university", "hide income.*avoid.*tax",
            "insider.*betting", "multi-level marketing.*scam",
            "insider trading", "counterfeit money",
            "ponzi scheme", "money laundering",
        ]
    },
    # --- Fraud / Deception ---
    "fraud": {
        "severity": "high",
        "keywords": [
            "ddos.*election", "fake charity",
            "fake weight loss drug", "fabricated.*reviews",
            "nigerian.*419.*scam", "blackmail.*deepfake",
            "illegally dump.*waste", "indoctrinate.*cult",
            "mail scam.*lottery", "bypass plagiarism",
            "phishing", "social engineering",
        ]
    },
    # --- Disinformation ---
    "disinformation": {
        "severity": "high",
        "keywords": [
            "fake news article.*disinformation",
            "september 11.*hoax", "holocaust.*never happened",
            "5g causes covid", "trump.*unanimously won",
            "global warming.*hoax", "vaccines cause autism",
            "earth is flat", "illuminati",
            "spread disinformation", "conspiracy theory",
            "fabricated evidence", "propaganda campaign",
        ]
    },
    # --- Sexual / Adult Content ---
    "sexual": {
        "severity": "critical",
        "keywords": [
            "explicit pornographic", "sexual conversations with strangers",
            "unprotected sex", "date rape drug",
            "child pornography", "csam",
            "intimate images", "sex with animals", "bestiality",
            "human trafficking.*sexual", "revenge porn",
            "glorifies.*pedophilia", "normalize.*pedophilia",
            "sexual exploitation",
        ]
    },
    # --- Privacy ---
    "privacy": {
        "severity": "high",
        "keywords": [
            "identity theft", "blackmail.*personal information",
            "facial recognition.*race", "fraudulent.*irs",
            "steal.*health records", "phishing email.*login credentials",
            "tracks user location without.*consent",
            "steal.*government database", "social security number",
            "clone debit cards", "dox", "doxxing",
        ]
    },
    # --- Expert Advice (Dangerous) ---
    "expert_advice": {
        "severity": "medium",
        "keywords": [
            "circumventing copyright", "pirating content",
            "medical treatment plan.*aids",
            "illegally prescribe opioid", "prescribe oxycontin",
            "guide for treating.*schizophrenia",
            "avoid.*convicted.*drunk driving",
            "recommends.*stocks.*financial gain",
            "extinguish.*fire without.*firefighters",
            "sell.*organs.*black market",
            "cheat.*smog test", "heroin.*coping.*depression",
        ]
    },
    # --- Government / Weapons ---
    "government": {
        "severity": "critical",
        "keywords": [
            "forge documents.*immigration",
            "alter criminal records", "tampering.*electronic monitoring",
            "exploit regulatory loopholes", "nuclear weapon",
            "shell companies.*government", "avoiding.*immigration authorities",
            "child labor.*manufacturing", "tamper.*voting machines",
            "vigilante justice", "biological weapon",
            "chemical weapon", "nerve agent",
        ]
    },
}




logger = logging.getLogger("GuardianAI.fast_path")

class FastPath:
    def __init__(self):
        # Known safe technical queries to reduce false positives
        self.allowlist_patterns = [
            r"explain the laws of thermodynamics",
            r"how does photosynthesis work",
            r"quantum mechanics basics",
            r"python list comprehension examples",
            r"what is a decorator in python",
            r"how to use git merge",
            r"hi there!?",
            r"hello!?",
            r"ping",
            r"summarize this text",
            r"summarize this normal request",
            r"normal prompt",
        ]
        self.allowlist_regex = [re.compile(p, re.IGNORECASE) for p in self.allowlist_patterns]

    def is_known_safe(self, prompt: str) -> bool:
        """Check if a prompt matches a known safe pattern."""
        for pattern in self.allowlist_regex:
            if pattern.search(prompt):
                logger.info(f"Fast-Path: Known safe pattern matched. Skipping AI check.")
                return True
        return False

    def is_known_malicious(self, prompt: str) -> bool:
        """
        Optional: Can add additional high-speed regex here 
        if not already handled by input_filter.
        """
        return False
