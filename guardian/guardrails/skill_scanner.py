import ast
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger("openclaw_guardian")

class SkillScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.blocked_imports = set(config.get('scanner', {}).get('blocked_imports', []))
        self.blocked_functions = set(config.get('scanner', {}).get('blocked_functions', []))

    def scan_directory(self, directory: str) -> List[str]:
        """
        Scans all python files in the directory.
        Returns a list of warnings/findings.
        """
        findings = []
        if not os.path.exists(directory):
            logger.warning(f"Skills directory not found: {directory}")
            return findings

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    file_findings = self.scan_file(full_path)
                    findings.extend(file_findings)
        
        return findings

    def scan_file(self, file_path: str) -> List[str]:
        findings = []
        try:
            # Visual effect: "Scanning [file]..."
            display_name = os.path.basename(file_path)
            # logger.info(f"Scanning {display_name}...") # Too noisy for logs, maybe print?
            # We'll use a special log format or just do it silently if we want clean logs.
            # But user asked for "real scanner" look.
            print(f"🔍 Scanning skill: {display_name} ...", end="", flush=True)
            import time
            time.sleep(0.05) # "Processing" delay

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            current_file_findings = []

            for node in ast.walk(tree):
                # Check imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in self.blocked_imports:
                            current_file_findings.append(f"⚠️  THREAT DETECTED: Illicit import '{alias.name}' in {display_name}")
                
                # Check from imports
                elif isinstance(node, ast.ImportFrom):
                    if node.module in self.blocked_imports:
                        current_file_findings.append(f"⚠️  THREAT DETECTED: Illicit import '{node.module}' in {display_name}")

                # Check function calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in self.blocked_functions:
                            current_file_findings.append(f"⚠️  RISK WARNING: Dangerous function '{node.func.id}' usage in {display_name}")
            
            findings.extend(current_file_findings)
            
            if current_file_findings:
                print(" [ THREAT FOUND ] ❌")
            else:
                print(" [ SAFE ] ✅")

        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
            print(f" [ ERROR ] ❓")
            
        return findings
