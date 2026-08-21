with open('guardian/web3sec/rpc_relay.py', 'r', encoding='utf-8') as f:
    content = f.read()

bad_sim = '''        if self.enforce_simulation:
            sim_res = self.sim_engine.simulate_transaction(tx)
            if not sim_res.success:
                if is_whitelisted:
                    logger.warning(f"Whitelisted address {to_addr or from_addr} bypassed simulation failure: {sim_res.revert_reason}")
                elif self.fail_mode == "closed":
                    self.stats["blocked"] += 1
                    return self._make_json_rpc_error(
                        -32000, f"Simulation failed: {sim_res.revert_reason}", req_id
                    )
                else:
                    logger.warning(f"Simulation failed (fail_mode=open, forwarding): {sim_res.revert_reason}")'''

good_sim = '''        if self.enforce_simulation:
            sim_res = self.sim_engine.simulate_transaction(tx)
            if not sim_res.success:
                if self.fail_mode == "closed":
                    self.stats["blocked"] += 1
                    return self._make_json_rpc_error(
                        -32000, f"Simulation failed: {sim_res.revert_reason}", req_id
                    )
                else:
                    logger.warning(f"Simulation failed (fail_mode=open, forwarding): {sim_res.revert_reason}")'''

content = content.replace(bad_sim, good_sim)

with open('guardian/web3sec/rpc_relay.py', 'w', encoding='utf-8') as f:
    f.write(content)
