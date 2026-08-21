import ast
import re
from typing import Dict, List

# Map from Vyper custom detector ARGUMENT to Guardian rule ID
VYPER_CUSTOM_MAP = {
    "guardian-vyper-unsafe-call": "SC-080",
    "guardian-vyper-timestamp": "SC-081",
}

class VyperASTAnalyzer(ast.NodeVisitor):
    def __init__(self, source_lines):
        self.source_lines = source_lines
        self.findings = {}
        for rule_id in VYPER_CUSTOM_MAP.values():
            self.findings[rule_id] = []
        
        # State tracking for SC-081
        self.timestamp_vars = set()

    def visit_Expr(self, node):
        # SC-080: Unsafe external call (unchecked raw_call)
        if isinstance(node.value, ast.Call):
            if getattr(node.value.func, 'id', '') == 'raw_call':
                line_no = getattr(node, 'lineno', 1)
                snippet = self.source_lines[line_no - 1].strip() if line_no <= len(self.source_lines) else "raw_call(...)"
                self.findings["SC-080"].append(snippet)
        self.generic_visit(node)

    def visit_Assign(self, node):
        if hasattr(node, 'targets') and len(node.targets) > 0:
            self._check_timestamp_assignment(node.targets[0], node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._check_timestamp_assignment(node.target, node.value)
        self.generic_visit(node)

    def _check_timestamp_assignment(self, target, value):
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            if value.value.id == 'block' and value.attr == 'timestamp':
                if isinstance(target, ast.Name):
                    self.timestamp_vars.add(target.id)

    def visit_BinOp(self, node):
        # SC-081: Unsafe timestamp use (block.timestamp % N)
        if isinstance(node.op, ast.Mod):
            if self._is_timestamp(node.left) or self._is_timestamp(node.right):
                line_no = getattr(node, 'lineno', 1)
                snippet = self.source_lines[line_no - 1].strip() if line_no <= len(self.source_lines) else "block.timestamp % ..."
                self.findings["SC-081"].append(snippet)
        self.generic_visit(node)

    def _is_timestamp(self, node):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return node.value.id == 'block' and node.attr == 'timestamp'
        if isinstance(node, ast.Name):
            return node.id in self.timestamp_vars
        return False

def run_vyper_ast_analysis(source_code: str) -> Dict[str, List[str]]:
    """
    Parses Vyper source code using Python's ast module.
    Returns a dict mapping Rule ID -> list of snippet strings.
    If parsing fails, returns None.
    """
    try:
        tree = ast.parse(source_code)
    except Exception:
        return None
    
    analyzer = VyperASTAnalyzer(source_code.splitlines())
    analyzer.visit(tree)
    return analyzer.findings
