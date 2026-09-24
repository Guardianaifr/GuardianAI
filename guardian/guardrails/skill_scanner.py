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
            display_name = os.path.basename(file_path)

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            current_file_findings = []

            for node in ast.walk(tree):
                # Check imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root_mod = alias.name.split(".")[0]
                        if alias.name in self.blocked_imports or root_mod in self.blocked_imports:
                            current_file_findings.append(f"⚠️  THREAT DETECTED: Illicit import '{alias.name}' in {display_name}")
                
                # Check from imports
                elif isinstance(node, ast.ImportFrom):
                    mod_name = node.module or ""
                    root_mod = mod_name.split(".")[0] if mod_name else ""
                    if mod_name in self.blocked_imports or (root_mod and root_mod in self.blocked_imports):
                        current_file_findings.append(f"⚠️  THREAT DETECTED: Illicit import '{mod_name}' in {display_name}")

                # Check function and method calls
                elif isinstance(node, ast.Call):
                    fn_name = None
                    if isinstance(node.func, ast.Name):
                        fn_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        fn_name = node.func.attr
                    if fn_name and fn_name in self.blocked_functions:
                        current_file_findings.append(f"⚠️  RISK WARNING: Dangerous function '{fn_name}' usage in {display_name}")
            
            findings.extend(current_file_findings)

        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
            
        return findings
