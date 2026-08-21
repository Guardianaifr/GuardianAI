with open('guardian/web3sec/tx_analyzer.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_func = '''    def analyze_transaction(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        for detector in self.detectors:
            if detector.enabled:
                result = detector.analyze(tx, sim_result)
                if result and result.blocked:
                    return result
        return None'''

new_func = '''    def analyze_transaction(self, tx: Dict[str, Any], sim_result: SimulationResult, live_rules: Optional[Dict[str, bool]] = None) -> Optional[AnalysisResult]:
        for detector in self.detectors:
            is_enabled = live_rules.get(detector.name, detector.enabled) if live_rules is not None else detector.enabled
            if is_enabled:
                result = detector.analyze(tx, sim_result)
                if result and result.blocked:
                    return result
        return None'''

content = content.replace(old_func, new_func)
with open('guardian/web3sec/tx_analyzer.py', 'w', encoding='utf-8') as f:
    f.write(content)
