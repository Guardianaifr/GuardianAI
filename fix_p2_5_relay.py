with open('guardian/web3sec/rpc_relay.py', 'r', encoding='utf-8') as f:
    content = f.read()

start = content.find('whitelist = self._load_whitelist_from_db()')
# back up to the # comment
start = content.rfind('#', 0, start)

end = content.find('if self.enforce_simulation:')
end = content.rfind('#', 0, end)

if start != -1 and end != -1:
    new_block = '''# Whitelist check
        whitelist = self._load_whitelist_from_db()
        to_addr = (tx.get("to") or "").lower()
        from_addr = (tx.get("from") or "").lower()
        is_whitelisted = to_addr in whitelist or from_addr in whitelist

        # Apply live rule flags from DB
        live_rules = self._load_rules_from_db()

        # Run detectors FIRST (calldata-only, no simulation needed)
        dummy_sim = SimulationResult(success=True, gas_used=0, return_data="")
        analysis_res = self.analyzer.analyze_transaction(tx, dummy_sim, live_rules=live_rules)
        if analysis_res and analysis_res.blocked:
            if is_whitelisted:
                logger.warning(f"Whitelisted address {to_addr or from_addr} bypassed {analysis_res.detector_name}: {analysis_res.reason}")
            else:
                self.stats["blocked"] += 1
                self._log_blocked(client_ip, tx.get("from", ""), tx.get("to", ""),
                                  analysis_res.detector_name, analysis_res.reason,
                                  analysis_res.severity, json.dumps(req_data))
                return self._make_json_rpc_error(
                    -32000, f"Guardian Security Block: {analysis_res.reason}", req_id
                )

        '''
    content = content[:start] + new_block + content[end:]
    with open('guardian/web3sec/rpc_relay.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Replaced block")
else:
    print("Could not find start/end")
