import re
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class GuardianAbstractDetector(AbstractDetector):
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = 'https://github.com/guardian'
    WIKI_TITLE = 'Guardian'
    WIKI_DESCRIPTION = '-'
    WIKI_EXPLOIT_SCENARIO = '-'
    WIKI_RECOMMENDATION = '-'

    def __init__(self, compilation_unit, slither, logger):
        super().__init__(compilation_unit, slither, logger)
        self.guardian_findings = []


class AccessControlDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-access-control'
    HELP = 'Missing Access Control on Sensitive Function (SC-031)'
    
    def _detect(self):
        results = []
        sensitive_patterns = [r'mint', r'pause', r'unpause', r'setowner', r'transferownership', r'withdraw', r'emergencywithdraw']
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                is_sensitive = any(re.search(p, function.name.lower()) for p in sensitive_patterns)
                if not is_sensitive:
                    is_sensitive = any(any(re.search(p, getattr(getattr(c, 'function', c), 'name', '').lower()) for p in sensitive_patterns) for c in function.internal_calls)
                if is_sensitive:
                    if function.visibility in ["public", "external"]:
                        has_modifier = any(
                            "onlyowner" in m.name.lower() or "onlyrole" in m.name.lower() or "auth" in m.name.lower() 
                            for m in function.modifiers
                        )
                        if not has_modifier:
                            self.guardian_findings.append(function.name)
                            info = [function, " lacks access control modifiers\n"]
                            res = self.generate_result(info)
                            results.append(res)
        return results


class UnprotectedInitializeDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-unprotected-init'
    HELP = 'Unprotected Initialize Function (SC-119)'

    # Anchored regex: match any public/external function whose name starts with
    # "initialize" or "init" (with optional leading underscore).
    # Examples caught: initialize, initializeV2, initToken, init, _init, _initialize.
    # Examples NOT caught: getInit, initial (neither starts with the target prefix alone).
    # The secondary state-variable-write check prevents false positives on functions
    # like initHelperLogging() that don't set owner/admin/initialized.
    _INIT_NAME_RE = re.compile(r'^_?(initialize|init)\w*$', re.IGNORECASE)

    # Guard modifier patterns: any modifier whose name contains these tokens signals
    # double-init protection (isInitializer, initializer, notInitialized, onlyDeploy …).
    _GUARD_MOD_RE = re.compile(
        r'init|initializ|notinit|onlyonce|isdeployer|notdeployed|once|guard|setup',
        re.IGNORECASE
    )

    # State variable name fragments that confirm this function initialises critical state.
    _CRITICAL_VARS = ("owner", "admin", "initialized", "paused", "deployer", "governor")

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # 1. Must match an initializer naming pattern.
                if not self._INIT_NAME_RE.match(function.name):
                    continue
                # 2. Must be externally callable.
                if function.visibility not in ["public", "external"]:
                    continue
                # 3. Must NOT carry a guard modifier that prevents double-init.
                has_guard = any(
                    self._GUARD_MOD_RE.search(m.name) for m in function.modifiers
                )
                if has_guard:
                    continue
                # 4. Confirm it writes critical state — distinguishes true initializers
                #    from helpers that merely contain the word "init" in their name.
                writes_critical = any(
                    any(kw in sv.name.lower() for kw in self._CRITICAL_VARS)
                    for sv in function.state_variables_written
                )
                if not writes_critical:
                    continue
                self.guardian_findings.append(function.name)
                info = [function, " is an unprotected initialize function\n"]
                results.append(self.generate_result(info))
        return results


class UncappedMintDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-uncapped-mint'
    HELP = 'Uncapped Minting (No Supply Ceiling) (SC-102)'

    _MINT_CALL = re.compile(r'_?mint', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # Only public/external functions — skip the internal _mint wrapper stub
                if function.visibility not in ['public', 'external']:
                    continue
                is_mint_name = 'mint' in function.name.lower()
                # Also catch renamed mint functions (createTokens, issue, etc.) that call _mint
                calls_internal_mint = any(
                    self._MINT_CALL.search(
                        getattr(getattr(call, 'function', call), 'name', '') or ''
                    )
                    for call in function.internal_calls
                )
                if not is_mint_name and not calls_internal_mint:
                    continue
                # Safe if function reads ANY cap/limit state variable (direct reads only)
                reads_cap = any(
                    'max' in v.name.lower() or
                    'cap' in v.name.lower() or
                    'limit' in v.name.lower() or
                    'ceiling' in v.name.lower() or
                    'total' in v.name.lower()
                    for v in function.state_variables_read
                )
                # Also safe if the function body contains a require guard
                # (Solidity constants like LIMIT are inlined; may not appear in state_variables_read)
                node_exprs = ' '.join(
                    str(n.expression) for n in function.nodes if n.expression is not None
                )
                # Cap-related require: require containing total/max/cap/limit
                has_cap_require = bool(re.search(
                    r'require\s*\([^)]*(?:total|max|cap|limit|ceiling)',
                    node_exprs, re.IGNORECASE
                ))
                if not reads_cap and not has_cap_require:
                    self.guardian_findings.append(function.name)
                    info = [function, " mints without a supply cap check\n"]
                    results.append(self.generate_result(info))
        return results


class FlashLoanAttackDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-flash-loan'
    HELP = 'Flash Loan Attack Vector (SC-060)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                has_flash = re.search(r'flashloan|flashswap|flashloanreceiver', function.name.lower())
                reads_price = any(re.search(r'getprice|spotprice|currentprice|getreserves', getattr(getattr(call, 'function', call), 'name', '').lower()) for call in function.internal_calls)
                if has_flash and reads_price:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses flash loans and reads spot prices\n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results


class SignatureReplayDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-signature-replay'
    HELP = 'Signature Replay / Missing Nonce (SC-111)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # Detect ecrecover calls (internal call or library call via name pattern)
                calls_ecrecover = any(
                    getattr(getattr(call, 'function', call), 'name', '') == 'ecrecover'
                    for call in function.internal_calls
                )
                # Also detect ECDSA-style library recover calls
                calls_ecdsa = any(
                    re.search(r'recover', getattr(getattr(call, 'function', call), 'name', '') or '', re.IGNORECASE)
                    for call in function.internal_calls
                )
                is_permit = 'permit' in function.name.lower()
                if calls_ecrecover or calls_ecdsa or is_permit:
                    # seq[] is a common nonce-equivalent (sequence counter)
                    reads_nonce = any(
                        'nonce' in v.name.lower() or 'seq' in v.name.lower()
                        for v in function.state_variables_read
                    )
                    if not reads_nonce:
                        self.guardian_findings.append(function.name)
                        info = [function, " processes signatures without a nonce/seq check\n"]
                        results.append(self.generate_result(info))
        return results

class GovernanceAttackDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-governance-attack'
    HELP = 'Governance Vote Manipulation (SC-116)'

    # Use word STEMS so both 'propose', 'proposal' and 'execute', 'executeProposal' match
    _GOV_STEMS = re.compile(r'vote|propos|execut|choice|submit', re.IGNORECASE)
    _FLASH_PATTERN = re.compile(r'flash', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                has_gov = self._GOV_STEMS.search(function.name)
                calls_flash = any(
                    self._FLASH_PATTERN.search(
                        getattr(getattr(call, 'function', call), 'name', '') or ''
                    )
                    for call in function.internal_calls
                )
                if has_gov and calls_flash:
                    self.guardian_findings.append(function.name)
                    info = [function, " mixes flash loans with governance actions\n"]
                    results.append(self.generate_result(info))
        return results

class MEVSandwichDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-mev-sandwich'
    HELP = 'Sandwich Attack Vector (MEV) (SC-114)'

    _AMM_CALLS = re.compile(r'addliquidity|provideliquidity|swapexact|addexact', re.IGNORECASE)
    _SLIPPAGE_GUARDS = re.compile(r'min|slippage|deadline|checkslippage', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # Check if this function CALLS any AMM operation (not just by function name)
                has_amm_call = any(
                    self._AMM_CALLS.search(
                        getattr(getattr(call, 'function', call), 'name', '') or ''
                    )
                    for call in function.internal_calls
                )
                if not has_amm_call:
                    continue
                # Safe if slippage guard is in parameters or called internally
                has_min_param = any(
                    self._SLIPPAGE_GUARDS.search(p.name.lower())
                    for p in function.parameters
                    if hasattr(p, 'name') and p.name
                )
                calls_slippage = any(
                    self._SLIPPAGE_GUARDS.search(
                        getattr(getattr(call, 'function', call), 'name', '') or ''
                    )
                    for call in function.internal_calls
                )
                if not has_min_param and not calls_slippage:
                    self.guardian_findings.append(function.name)
                    info = [function, " executes AMM operation without slippage protection\n"]
                    results.append(self.generate_result(info))
        return results

class NoTimelockDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-no-timelock'
    HELP = 'No Timelock on Role Changes (SC-101)'

    _ROLE_NAMES = re.compile(r'grantrole|revokerole|assignrole|setrole', re.IGNORECASE)
    _ROLE_CALLS = re.compile(r'^(?:_?grant|_?revoke|_?assign)role$', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            inherits_timelock = any('timelock' in c.name.lower() for c in contract.inheritance)
            if inherits_timelock:
                continue
            for function in contract.functions:
                if function.visibility not in ['public', 'external']:
                    continue
                # ANY modifier provides access control — skip guarded functions
                if bool(function.modifiers):
                    continue
                name_match = self._ROLE_NAMES.search(function.name)
                calls_role = any(
                    self._ROLE_CALLS.match(
                        getattr(getattr(call, 'function', call), 'name', '') or ''
                    )
                    for call in function.internal_calls
                )
                if name_match or calls_role:
                    self.guardian_findings.append(function.name)
                    info = [function, " changes roles without access guard or Timelock\n"]
                    results.append(self.generate_result(info))
        return results

class OracleCentralizationDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-oracle-centralization'
    HELP = 'Oracle Centralization (SC-122)'

    _GETTER_NAMES = re.compile(r'getprice|fetchprice|latestanswer|getlastprice|currentprice|price', re.IGNORECASE)
    _SETTER_NAMES = re.compile(r'setoracle|priceoracle', re.IGNORECASE)
    _AGGREGATION = re.compile(r'median|average|twap|aggregate|vwap', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # Original: setter-style admin functions
                if self._SETTER_NAMES.search(function.name) and function.visibility in ['public', 'external']:
                    self.guardian_findings.append(function.name)
                    results.append(self.generate_result([function, " allows centralized oracle update\n"]))
                    continue
                # New: getter functions using a single oracle source without aggregation
                if self._GETTER_NAMES.search(function.name) and function.visibility in ['public', 'external']:
                    # Skip modifier-guarded wrapper stubs (e.g. spotPrice() nonReentrant)
                    if bool(function.modifiers):
                        continue
                    # Scan node expression strings — more reliable than internal_calls chain
                    node_exprs = ' '.join(
                        str(n.expression) for n in function.nodes if n.expression is not None
                    )
                    uses_aggregation = bool(self._AGGREGATION.search(node_exprs))
                    # Count distinct oracle-related state vars read
                    oracle_reads = [
                        v for v in function.state_variables_read
                        if re.search(r'oracle|price', v.name.lower())
                    ]
                    if not uses_aggregation and len(oracle_reads) <= 1:
                        self.guardian_findings.append(function.name)
                        results.append(self.generate_result([function, " returns single-source oracle price\n"]))
        return results

class ReentrancyDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-reentrancy'
    HELP = 'Reentrancy (SC-001)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:  # functions only — not modifiers
                call_node = None
                for node in function.nodes:
                    # Use Slither structured tracking first; fall back to string inspection.
                    # Anchor to ".call" (with dot) so we don't accidentally match
                    # identifiers that contain the word "call".
                    has_lowlevel = bool(getattr(node, 'low_level_calls', []))
                    expr = str(node.expression) if node.expression is not None else ""
                    has_str_call = (
                        ".call" in expr.lower() and
                        ".delegatecall" not in expr.lower() and
                        ".staticcall" not in expr.lower()
                    )
                    if has_lowlevel or has_str_call:
                        call_node = node
                        break

                if call_node is None:
                    continue

                # CEI violation: state written AFTER the external call
                writes_after = any(
                    node.node_id > call_node.node_id and
                    bool(getattr(node, 'state_variables_written', []))
                    for node in function.nodes
                )
                if writes_after:
                    self.guardian_findings.append(function.name)
                    info = [function, " modifies state after external call (reentrancy)\n"]
                    results.append(self.generate_result(info))
        return results

class SC002Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-no-reentrancy-guard'
    HELP = 'No Reentrancy Guard on External Call (SC-002)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                if function.visibility not in ["external", "public"]:
                    continue
                if function.is_constructor_variables or getattr(function, "is_fallback", False) or getattr(function, "is_receive", False):
                    continue
                
                # Check if it makes external calls
                has_external_call = len(function.high_level_calls) > 0 or len(function.low_level_calls) > 0
                # Fallback to string matching for .call in case Slither misses unstructured sends
                if not has_external_call:
                    for node in function.nodes:
                        expr = str(node.expression) if node.expression is not None else ""
                        if ".call" in expr.lower() or ".send" in expr.lower():
                            has_external_call = True
                            break
                            
                if has_external_call:
                    has_guard = any("reentrant" in m.name.lower() or "lock" in m.name.lower() for m in function.modifiers)
                    if not has_guard:
                        self.guardian_findings.append(function.name)
                        info = [function, " makes external calls without a reentrancy guard\n"]
                        results.append(self.generate_result(info))
        return results

class SC010Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-front-running'
    HELP = 'Front-Running via Transaction Ordering (SC-010)'

    def _detect(self):
        results = []
        trade_keywords = ["swap", "trade", "exchange", "buy", "sell"]
        safe_params = ["min", "deadline", "amountoutmin", "limit"]
        
        for contract in self.contracts:
            for function in contract.functions:
                if function.visibility not in ["external", "public"]:
                    continue
                if function.is_constructor_variables or getattr(function, "is_fallback", False) or getattr(function, "is_receive", False):
                    continue
                
                fname = function.name.lower()
                is_trade = any(kw in fname for kw in trade_keywords)
                
                if is_trade:
                    # Check if parameters offer protection
                    has_protection = False
                    for param in function.parameters:
                        pname = param.name.lower()
                        if any(sp in pname for sp in safe_params):
                            has_protection = True
                            break
                            
                    if not has_protection:
                        self.guardian_findings.append(function.name)
                        info = [function, " lacks front-running/slippage protection parameters (minOut, deadline)\n"]
                        results.append(self.generate_result(info))
        return results

class SC011Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-missing-slippage'
    HELP = 'Missing Slippage Protection (SC-011)'

    def _detect(self):
        results = []
        trade_keywords = ["swap", "trade", "exchange"]
        safe_params = ["amountoutmin", "minout", "minamount", "deadline"]
        
        for contract in self.contracts:
            for function in contract.functions:
                if function.visibility not in ["external", "public"]:
                    continue
                if function.is_constructor_variables or getattr(function, "is_fallback", False) or getattr(function, "is_receive", False):
                    continue
                
                fname = function.name.lower()
                is_trade = any(kw in fname for kw in trade_keywords)
                
                if is_trade:
                    # Check if parameters offer standard slippage protection
                    has_protection = False
                    for param in function.parameters:
                        pname = param.name.lower()
                        if any(sp in pname for sp in safe_params):
                            has_protection = True
                            break
                            
                    if not has_protection:
                        self.guardian_findings.append(function.name)
                        info = [function, " lacks standard slippage protection parameters\n"]
                        results.append(self.generate_result(info))
        return results

class SC061Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-spot-price-oracle'
    HELP = 'Spot Price Oracle Manipulation (SC-061)'

    def _detect(self):
        results = []
        spot_keywords = ["getreserves", "reserves(", "getamountsout", "getamountsin"]
        safe_keywords = ["twap", "chainlink", "oracle", "consult"]
        
        for contract in self.contracts:
            for function in contract.functions:
                has_spot = False
                has_safe = False
                
                for node in function.nodes:
                    expr = str(node.expression).lower() if node.expression else ""
                    if any(k in expr for k in spot_keywords):
                        has_spot = True
                    if any(k in expr for k in safe_keywords):
                        has_safe = True
                
                if has_spot and not has_safe:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses AMM spot price reserves without TWAP/Oracle\n"]
                    results.append(self.generate_result(info))
        return results

class SC100Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-single-eoa-admin'
    HELP = 'Single-EOA Admin / No Multisig (SC-100)'

    def _detect(self):
        results = []
        admin_keywords = ["owner", "admin"]
        safe_keywords = ["multisig", "safe", "governor", "timelock"]
        
        for contract in self.contracts:
            # Check state variables
            for var in contract.state_variables:
                vname = var.name.lower()
                is_admin = any(kw in vname for kw in admin_keywords)
                if is_admin:
                    is_safe = any(kw in vname for kw in safe_keywords)
                    if not is_safe:
                        self.guardian_findings.append(var.name)
                        info = [var, " is a single-EOA admin without multisig/timelock\n"]
                        results.append(self.generate_result(info))
                        
            # Check inherited contracts
            for inherited in contract.inheritance:
                iname = inherited.name.lower()
                is_admin = any(kw in iname for kw in ["ownable", "accesscontrol"])
                if is_admin:
                    is_safe = any(kw in iname for kw in safe_keywords)
                    if not is_safe:
                        self.guardian_findings.append(inherited.name)
                        info = [inherited, " inherits single-admin pattern without multisig/timelock\n"]
                        results.append(self.generate_result(info))
                        
        return results

class SC103Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-admin-mint'
    HELP = 'Admin Can Directly Mint Tokens (SC-103)'

    def _detect(self):
        results = []
        admin_modifiers = ["onlyowner", "onlyadmin"]
        safe_modifiers = ["onlytimelock", "onlyminter", "onlygovernance"]
        
        for contract in self.contracts:
            for function in contract.functions:
                if function.visibility not in ["external", "public"]:
                    continue
                
                fname = function.name.lower()
                is_mint = "mint" in fname or "issue" in fname
                
                if not is_mint:
                    for call in function.internal_calls:
                        cname = getattr(call, "function_name", "") or getattr(getattr(call, "function", None), "name", "")
                        if cname and "mint" in cname.lower():
                            is_mint = True
                            break
                            
                if is_mint:
                    has_admin_mod = False
                    has_safe_mod = False
                    for mod in function.modifiers:
                        mname = mod.name.lower()
                        if any(k in mname for k in admin_modifiers):
                            has_admin_mod = True
                        if any(k in mname for k in safe_modifiers):
                            has_safe_mod = True
                            
                    if has_admin_mod and not has_safe_mod:
                        self.guardian_findings.append(function.name)
                        info = [function, " allows direct minting by single admin (e.g. onlyOwner)\n"]
                        results.append(self.generate_result(info))
        return results

class SC104Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-instant-role'
    HELP = 'Instant Role Grant (SC-104)'

    def _detect(self):
        results = []
        role_funcs = ["_grantrole", "_setuprole", "_setroleadmin"]
        safe_keywords = ["delay", "propose", "timelock"]
        
        for contract in self.contracts:
            for function in contract.functions:
                if function.visibility not in ["external", "public"]:
                    continue
                
                grants_role = False
                for call in function.internal_calls:
                    cname = getattr(call, "function_name", "") or getattr(getattr(call, "function", None), "name", "")
                    if cname and cname.lower() in role_funcs:
                        grants_role = True
                        break
                            
                if grants_role:
                    # Check for delay/timelock in modifiers or source code
                    is_safe = False
                    for mod in function.modifiers:
                        if any(k in mod.name.lower() for k in safe_keywords):
                            is_safe = True
                            
                    try:
                        source_code = function.source_mapping.content.lower()
                        if any(k in source_code for k in safe_keywords):
                            is_safe = True
                    except Exception:
                        pass
                        
                    if not is_safe:
                        self.guardian_findings.append(function.name)
                        info = [function, " grants role instantly without delay/timelock\n"]
                        results.append(self.generate_result(info))
        return results

class SC106Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-collateral-freshness'
    HELP = 'No Collateral Freshness Check (SC-106)'

    def _detect(self):
        results = []
        vuln_keywords = ["depositcollateral", "borrow", "addcollateral", "supplycollateral"]
        safe_keywords = ["totalsupply", "liquidity", "oracle", "pricecheck", "whitelist", "approved"]
        
        for contract in self.contracts:
            for function in contract.functions:
                if function.visibility not in ["external", "public"]:
                    continue
                
                fname = function.name.lower()
                is_vuln_func = False
                if any(k in fname for k in vuln_keywords) or ("collateral" in fname and any(k in fname for k in ["deposit", "supply", "add"])):
                    is_vuln_func = True
                    
                if is_vuln_func:
                    is_safe = False
                    try:
                        source_code = function.source_mapping.content.lower()
                        if any(k in source_code for k in safe_keywords):
                            is_safe = True
                    except Exception:
                        pass
                        
                    # Also check modifiers just in case
                    for mod in function.modifiers:
                        if any(k in mod.name.lower() for k in safe_keywords):
                            is_safe = True
                            
                    if not is_safe:
                        self.guardian_findings.append(function.name)
                        info = [function, " lacks collateral freshness/supply checks\n"]
                        results.append(self.generate_result(info))
        return results

class SC107Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-role-monitor'
    HELP = 'Missing Role-Change Event Monitoring (SC-107)'

    def _detect(self):
        results = []
        safe_keywords = ["forta", "defender", "monitor", "adminchanged"]
        
        for contract in self.contracts:
            is_access_control = False
            for inherited in contract.inheritance:
                iname = inherited.name.lower()
                if "accesscontrol" in iname or "ownable" in iname:
                    is_access_control = True
                    break
                    
            # Check variables in case it's not inherited directly
            if not is_access_control:
                for var in contract.state_variables:
                    vname = var.name.lower()
                    if "owner" in vname or "admin" in vname:
                        is_access_control = True
                        break
                        
            if is_access_control:
                is_safe = False
                try:
                    source_code = contract.source_mapping.content.lower()
                    if any(k in source_code for k in safe_keywords):
                        is_safe = True
                except Exception:
                    pass
                    
                if not is_safe:
                    # Ignore the base contracts themselves if they are just empty definitions in the test file
                    if contract.name.lower() in ["accesscontrol", "ownable"]:
                        continue
                    self.guardian_findings.append(contract.name)
                    info = [contract, " uses AccessControl/Ownable without monitoring (Forta/Defender)\n"]
                    results.append(self.generate_result(info))
        return results

class SC110Detector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-bridge-replay'
    HELP = 'Cross-Chain Bridge Replay (SC-110)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                uses_recover = False
                
                # 1. Check for ecrecover or ECDSA.recover in source code
                try:
                    src = function.source_mapping.content.lower()
                    if "ecrecover" in src or "ecdsa.recover" in src:
                        uses_recover = True
                except Exception:
                    # Fallback to checking expressions
                    for node in function.nodes:
                        if node.expression:
                            expr_str = str(node.expression).lower()
                            if "ecrecover" in expr_str or "recover" in expr_str:
                                uses_recover = True
                                break
                                
                if uses_recover:
                    is_safe = False
                    
                    # 2. Check if chainid or domain_separator is used in the function
                    # Check Solidity variables read (e.g. block.chainid)
                    for node in function.nodes:
                        if node.solidity_variables_read:
                            for var in node.solidity_variables_read:
                                if "chainid" in var.name.lower():
                                    is_safe = True
                        if node.state_variables_read:
                            for var in node.state_variables_read:
                                if "domain_separator" in var.name.lower():
                                    is_safe = True
                                    
                    # Check source code text as well
                    try:
                        src = function.source_mapping.content.lower()
                        if "chainid" in src or "domain_separator" in src:
                            is_safe = True
                    except Exception:
                        pass
                        
                    if not is_safe:
                        self.guardian_findings.append(function.name)
                        info = [function, " calls ecrecover/ECDSA.recover without chainId or DOMAIN_SEPARATOR validation\n"]
                        results.append(self.generate_result(info))
        return results


class DelegatecallDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-delegatecall'
    HELP = 'Delegatecall Misuse (SC-041)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:  # functions only — not modifiers
                param_names = {
                    p.name.lower()
                    for p in function.parameters
                    if hasattr(p, 'name') and p.name
                }
                flagged = False
                for node in function.nodes:
                    expr = str(node.expression) if node.expression is not None else ""
                    if ".delegatecall" not in expr.lower():
                        continue
                    # Extract the receiver (the identifier BEFORE .delegatecall).
                    # Only flag when the receiver itself is a user-supplied parameter.
                    # The call-data argument (e.g. `data`) is allowed to be a param —
                    # that is standard proxy behaviour. The DANGER is a user-controlled
                    # TARGET address.
                    m = re.search(r'(\w+)\.delegatecall\s*\(', expr, re.IGNORECASE)
                    if m:
                        receiver = m.group(1).lower()
                        if receiver in param_names:
                            flagged = True
                            break
                if flagged:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses delegatecall with user-controlled target\n"]
                    results.append(self.generate_result(info))
        return results

class IntegerOverflowDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-integer-overflow'
    HELP = 'Integer Overflow (SC-020)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:  # functions only
                for node in function.nodes:
                    expr = str(node.expression) if node.expression is not None else ""
                    # Solidity 0.8+ allows opting out of overflow checks via `unchecked`.
                    # Flag any unchecked block — caller is responsible for bounds.
                    if re.search(r'\bunchecked\b', expr, re.IGNORECASE):
                        self.guardian_findings.append(function.name)
                        info = [function, " uses unchecked arithmetic block\n"]
                        results.append(self.generate_result(info))
                        break  # one finding per function
        return results

class TxOriginDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-tx-origin'
    HELP = 'tx.origin Authentication (SC-030)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                flagged = False
                for node in function.nodes:
                    expr = str(node.expression) if node.expression is not None else ""
                    if "tx.origin" not in expr.lower():
                        continue
                    # EOA guard: tx.origin == msg.sender (or reversed) is a SAFE pattern.
                    # It is used to prevent contracts from calling a function — NOT for auth.
                    # Normalise whitespace so both orderings are caught regardless of
                    # how Slither serialises the expression.
                    expr_norm = re.sub(r'\s+', '', expr).lower()
                    is_eoa_guard = (
                        "msg.sender==tx.origin" in expr_norm or
                        "tx.origin==msg.sender" in expr_norm
                    )
                    if not is_eoa_guard:
                        flagged = True
                        break  # one hit per function is enough
                if flagged:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses tx.origin for authentication\n"]
                    results.append(self.generate_result(info))
        return results

class SelfdestructDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-selfdestruct'
    HELP = 'selfdestruct (SC-042)'

    _KILL_NAMES = re.compile(r'kill|destroy|suicide|terminate', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:  # functions only
                # ANY modifier signals access control — skip guarded functions.
                has_modifier = bool(function.modifiers)
                if has_modifier:
                    continue
                flagged = False
                for node in function.nodes:
                    expr = str(node.expression) if node.expression is not None else ""
                    # Direct selfdestruct / suicide
                    if re.search(r'\b(?:selfdestruct|suicide)\s*\(', expr, re.IGNORECASE):
                        flagged = True
                        break
                    # Indirect: empty delegatecall (invokes fallback which may selfdestruct)
                    # Flag only when the function is named something destructive to avoid
                    # broad FPs on legitimate empty delegatecalls elsewhere.
                    if (re.search(r'\.delegatecall\s*\(\s*["\']\s*["\']\s*\)', expr) and
                            self._KILL_NAMES.search(function.name)):
                        flagged = True
                        break
                if flagged:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses selfdestruct without access guard\n"]
                    results.append(self.generate_result(info))
        return results

class TimestampDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-timestamp'
    HELP = 'Timestamp Dependence (SC-050)'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # ── Step 1: does this function read block.timestamp? ──────────────
                # function.variables_read (function-level) includes SolidityVariableComposed
                # objects such as block.timestamp.  str() of such objects returns their
                # canonical name (e.g. "block.timestamp").
                reads_timestamp = any(
                    str(v) in ("block.timestamp", "now")
                    for v in function.variables_read
                )
                # Belt-and-suspenders: fall back to scanning raw node expression strings
                # in case Slither's variable tracking omits the SolidityVariableComposed
                # in this version.
                if not reads_timestamp:
                    reads_timestamp = any(
                        "block.timestamp" in (str(node.expression)
                                              if node.expression is not None else "")
                        for node in function.nodes
                    )
                if not reads_timestamp:
                    continue

                # ── Step 2: is the timestamp use security-critical? ───────────────
                # A purely cosmetic use (e.g. returning a UI theme, or a view returning
                # a time delta) has no state writes and no internal calls.
                # Security-critical uses call functions that write state or transfer
                # value (e.g. win(), distribute(), etc.).
                writes_state = bool(function.state_variables_written)
                has_internal_call = bool(function.internal_calls)

                if writes_state or has_internal_call:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses block.timestamp in security-critical logic\n"]
                    results.append(self.generate_result(info))
        return results

class UnverifiedProxyDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-unverified-proxy'
    HELP = 'Unverified Proxy (SC-105)'

    # Known-safe EIP-standard proxy base names
    _SAFE_BASES = re.compile(
        r'ERC1967|TransparentUpgradeable|UUPSUpgradeable|BeaconProxy',
        re.IGNORECASE
    )
    _PROXY_KEYWORDS = re.compile(r'proxy|upgradeable', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            is_proxy = False
            is_verified = False

            # Signal 1: fallback/receive contains delegatecall to implementation slot
            for function in contract.functions:
                if function.is_fallback or function.is_receive:
                    for node in function.nodes:
                        expr = str(node.expression) if node.expression is not None else ""
                        if "delegatecall" in expr.lower() and "implementation" in expr.lower():
                            is_proxy = True

            # Signal 2: contract inherits from a proxy base class
            for base in contract.inheritance:
                if self._PROXY_KEYWORDS.search(base.name):
                    is_proxy = True
                    if self._SAFE_BASES.search(base.name):
                        is_verified = True  # well-known OZ/EIP proxy — treat as auditable

            if is_proxy and not is_verified:
                self.guardian_findings.append(contract.name)
                info = [contract, " uses an unverified proxy pattern\n"]
                results.append(self.generate_result(info))
        return results

class ReadOnlyReentrancyDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-read-only-reentrancy'
    HELP = 'Read-Only Reentrancy (SC-113)'

    _CRITICAL_NAMES = re.compile(
        r'getprice|getreserve|getbalance|price|reserve|spot',
        re.IGNORECASE
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # Only check view/pure functions that return financial state
                if not getattr(function, 'view', False):
                    continue
                if not self._CRITICAL_NAMES.search(function.name):
                    continue
                # Safe if protected by nonReentrant or a locking modifier
                has_reentrancy_guard = any(
                    'nonreentrant' in m.name.lower() or 'lock' in m.name.lower()
                    for m in function.modifiers
                )
                if not has_reentrancy_guard:
                    self.guardian_findings.append(function.name)
                    info = [function, " is an unprotected view function (read-only reentrancy risk)\n"]
                    results.append(self.generate_result(info))
        return results

class StorageCollisionDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-storage-collision'
    HELP = 'Storage Collision (SC-112)'

    _PROXY_KEYWORDS = re.compile(r'proxy', re.IGNORECASE)
    _SAFE_KEYWORDS = re.compile(r'diamond|eip1967|1967', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            # Check if contract inherits from any proxy-like base
            is_proxy = any(self._PROXY_KEYWORDS.search(b.name) for b in contract.inheritance)
            if not is_proxy:
                continue
            # Check if it uses safe storage patterns (diamond storage or EIP-1967 slots)
            uses_safe_storage = any(
                self._SAFE_KEYWORDS.search(v.name)
                for v in contract.state_variables
            )
            # Also check for bytes32 constant slot variables (EIP-1967 pattern)
            has_slot_constant = any(
                v.is_constant and str(v.type) == 'bytes32'
                for v in contract.state_variables
            )
            if not uses_safe_storage and not has_slot_constant:
                self.guardian_findings.append(contract.name)
                info = [contract, " may have storage collision with proxy contract\n"]
                results.append(self.generate_result(info))
        return results


class MissingDeadlineDetector(GuardianAbstractDetector):
    ARGUMENT = "guardian-missing-deadline"
    HELP = "Missing or hardcoded deadline in swap operations"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/missing-deadline"
    WIKI_TITLE = "Missing Deadline"
    WIKI_DESCRIPTION = "AMM swaps must have a validated deadline parameter to prevent delayed execution attacks."
    WIKI_EXPLOIT_SCENARIO = "Miners can hold the transaction and execute it when the price is favorable to them, resulting in a loss for the user."
    WIKI_RECOMMENDATION = "Pass a reasonable deadline, such as block.timestamp + N."

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_declared:
                if function.is_constructor:
                    continue
                for node in function.nodes:
                    for ir in node.irs:
                        from slither.slithir.operations import HighLevelCall
                        from slither.slithir.variables import Constant
                        if isinstance(ir, HighLevelCall):
                            func_name = ""
                            if hasattr(ir, 'function') and ir.function:
                                func_name = ir.function.name
                            elif hasattr(ir, 'function_name'):
                                if isinstance(ir.function_name, str):
                                    func_name = ir.function_name
                                elif hasattr(ir.function_name, 'value'):
                                    func_name = str(ir.function_name.value)
                            
                            if 'swap' in func_name.lower():
                                if ir.arguments:
                                    last_arg = ir.arguments[-1]
                                    is_vuln = False
                                    if isinstance(last_arg, Constant):
                                        if str(last_arg.value) == '0':
                                            is_vuln = True
                                    elif hasattr(last_arg, 'name') and 'timestamp' in str(last_arg.name).lower():
                                        is_vuln = True
                                    
                                    if is_vuln:
                                        self.guardian_findings.append(func_name)
                                        info = [node, " uses hardcoded 0 or timestamp as deadline in swap\n"]
                                        res = self.generate_result(info)
                                        results.append(res)
        return results

class UncheckedArithmeticDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-unchecked-arithmetic'
    HELP = 'Unchecked Arithmetic Block (SC-021)'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://example.com/unchecked-math"
    WIKI_TITLE = "Unchecked Math"
    WIKI_DESCRIPTION = "Use of unchecked blocks bypasses Solidity overflow protection."
    WIKI_EXPLOIT_SCENARIO = "Attackers can overflow/underflow variables."
    WIKI_RECOMMENDATION = "Remove unnecessary unchecked blocks, or add explicit bounds checks."

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                is_vuln = False
                source = function.source_mapping.content if function.source_mapping else ''
                if 'unchecked' in source:
                    is_vuln = True
                
                if not is_vuln:
                    for node in function.nodes:
                        if getattr(node, 'type', None).__class__.__name__ == 'NodeType':
                            if node.type.name == 'ASSEMBLY':
                                node_source = node.source_mapping.content if node.source_mapping else ''
                                import re
                                if re.search(r'\b(add|sub|mul|div)\b', node_source):
                                    is_vuln = True
                                    break
                
                if is_vuln:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses unchecked arithmetic block or assembly math\n"]
                    results.append(self.generate_result(info))
        return results

class DefaultVisibilityDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-default-visibility'
    HELP = 'Default Function Visibility (SC-032)'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/default-visibility"
    WIKI_TITLE = "Default Visibility"
    WIKI_DESCRIPTION = "Functions without explicit visibility default to public in older Solidity."
    WIKI_EXPLOIT_SCENARIO = "An internal function defaults to public."
    WIKI_RECOMMENDATION = "Always declare explicit visibility."

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                if function.is_constructor or function.is_fallback or function.is_receive:
                    continue
                source = function.source_mapping.content if function.source_mapping else ''
                # Hybrid check: use regex on the source mapping of the function
                import re
                if re.search(r'function\s+\w+\s*\([^)]*\)(?![^{]*(?:public|external|internal|private))[^{]*\{', source):
                    self.guardian_findings.append(function.name)
                    info = [function, " has implicit default visibility\n"]
                    results.append(self.generate_result(info))
        return results
class DonationAttackDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-donation-attack'
    HELP = 'Donation Attack / Vault Inflation (SC-117)'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://example.com/donation-attack"
    WIKI_TITLE = "Donation Attack"
    WIKI_DESCRIPTION = "Vault share minting may be manipulable by pre-deposit donation/inflation patterns."
    WIKI_EXPLOIT_SCENARIO = "An attacker sends tokens directly to the vault to inflate the exchange rate."
    WIKI_RECOMMENDATION = "Use ERC-4626 anti-inflation controls and minimum share mint thresholds."

    def _detect(self):
        results = []
        for contract in self.contracts:
            has_vault_calc = False
            has_donation = False
            vuln_funcs = []
            
            for function in contract.functions_and_modifiers:
                name_lower = function.name.lower()
                if any(x in name_lower for x in ['totalassets', 'converttoshares', 'previewdeposit']):
                    has_vault_calc = True
                    vuln_funcs.append(function)
                if any(x in name_lower for x in ['donate', 'skim', 'first_depositor', 'firstdepositor']):
                    has_donation = True
                    vuln_funcs.append(function)
            
    ARGUMENT = 'guardian-read-only-reentrancy'
    HELP = 'Read-Only Reentrancy (SC-113)'

    _CRITICAL_NAMES = re.compile(
        r'getprice|getreserve|getbalance|price|reserve|spot',
        re.IGNORECASE
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                # Only check view/pure functions that return financial state
                if not getattr(function, 'view', False):
                    continue
                if not self._CRITICAL_NAMES.search(function.name):
                    continue
                # Safe if protected by nonReentrant or a locking modifier
                has_reentrancy_guard = any(
                    'nonreentrant' in m.name.lower() or 'lock' in m.name.lower()
                    for m in function.modifiers
                )
                if not has_reentrancy_guard:
                    self.guardian_findings.append(function.name)
                    info = [function, " is an unprotected view function (read-only reentrancy risk)\n"]
                    results.append(self.generate_result(info))
        return results

class StorageCollisionDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-storage-collision'
    HELP = 'Storage Collision (SC-112)'

    _PROXY_KEYWORDS = re.compile(r'proxy', re.IGNORECASE)
    _SAFE_KEYWORDS = re.compile(r'diamond|eip1967|1967', re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            # Check if contract inherits from any proxy-like base
            is_proxy = any(self._PROXY_KEYWORDS.search(b.name) for b in contract.inheritance)
            if not is_proxy:
                continue
            # Check if it uses safe storage patterns (diamond storage or EIP-1967 slots)
            uses_safe_storage = any(
                self._SAFE_KEYWORDS.search(v.name)
                for v in contract.state_variables
            )
            # Also check for bytes32 constant slot variables (EIP-1967 pattern)
            has_slot_constant = any(
                v.is_constant and str(v.type) == 'bytes32'
                for v in contract.state_variables
            )
            if not uses_safe_storage and not has_slot_constant:
                self.guardian_findings.append(contract.name)
                info = [contract, " may have storage collision with proxy contract\n"]
                results.append(self.generate_result(info))
        return results


class MissingDeadlineDetector(GuardianAbstractDetector):
    ARGUMENT = "guardian-missing-deadline"
    HELP = "Missing or hardcoded deadline in swap operations"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/missing-deadline"
    WIKI_TITLE = "Missing Deadline"
    WIKI_DESCRIPTION = "AMM swaps must have a validated deadline parameter to prevent delayed execution attacks."
    WIKI_EXPLOIT_SCENARIO = "Miners can hold the transaction and execute it when the price is favorable to them, resulting in a loss for the user."
    WIKI_RECOMMENDATION = "Pass a reasonable deadline, such as block.timestamp + N."

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_declared:
                if function.is_constructor:
                    continue
                for node in function.nodes:
                    for ir in node.irs:
                        from slither.slithir.operations import HighLevelCall
                        from slither.slithir.variables import Constant
                        if isinstance(ir, HighLevelCall):
                            func_name = ""
                            if hasattr(ir, 'function') and ir.function:
                                func_name = ir.function.name
                            elif hasattr(ir, 'function_name'):
                                if isinstance(ir.function_name, str):
                                    func_name = ir.function_name
                                elif hasattr(ir.function_name, 'value'):
                                    func_name = str(ir.function_name.value)
                            
                            if 'swap' in func_name.lower():
                                if ir.arguments:
                                    last_arg = ir.arguments[-1]
                                    is_vuln = False
                                    if isinstance(last_arg, Constant):
                                        if str(last_arg.value) == '0':
                                            is_vuln = True
                                    elif hasattr(last_arg, 'name') and 'timestamp' in str(last_arg.name).lower():
                                        is_vuln = True
                                    
                                    if is_vuln:
                                        self.guardian_findings.append(func_name)
                                        info = [node, " uses hardcoded 0 or timestamp as deadline in swap\n"]
                                        res = self.generate_result(info)
                                        results.append(res)
        return results

class UncheckedArithmeticDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-unchecked-arithmetic'
    HELP = 'Unchecked Arithmetic Block (SC-021)'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://example.com/unchecked-math"
    WIKI_TITLE = "Unchecked Math"
    WIKI_DESCRIPTION = "Use of unchecked blocks bypasses Solidity overflow protection."
    WIKI_EXPLOIT_SCENARIO = "Attackers can overflow/underflow variables."
    WIKI_RECOMMENDATION = "Remove unnecessary unchecked blocks, or add explicit bounds checks."

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                is_vuln = False
                source = function.source_mapping.content if function.source_mapping else ''
                if 'unchecked' in source:
                    is_vuln = True
                
                if not is_vuln:
                    for node in function.nodes:
                        if getattr(node, 'type', None).__class__.__name__ == 'NodeType':
                            if node.type.name == 'ASSEMBLY':
                                node_source = node.source_mapping.content if node.source_mapping else ''
                                import re
                                if re.search(r'\b(add|sub|mul|div)\b', node_source):
                                    is_vuln = True
                                    break
                
                if is_vuln:
                    self.guardian_findings.append(function.name)
                    info = [function, " uses unchecked arithmetic block or assembly math\n"]
                    results.append(self.generate_result(info))
        return results

class DefaultVisibilityDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-default-visibility'
    HELP = 'Default Function Visibility (SC-032)'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/default-visibility"
    WIKI_TITLE = "Default Visibility"
    WIKI_DESCRIPTION = "Functions without explicit visibility default to public in older Solidity."
    WIKI_EXPLOIT_SCENARIO = "An internal function defaults to public."
    WIKI_RECOMMENDATION = "Always declare explicit visibility."

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                if function.is_constructor or function.is_fallback or function.is_receive:
                    continue
                source = function.source_mapping.content if function.source_mapping else ''
                # Hybrid check: use regex on the source mapping of the function
                import re
                if re.search(r'function\s+\w+\s*\([^)]*\)(?![^{]*(?:public|external|internal|private))[^{]*\{', source):
                    self.guardian_findings.append(function.name)
                    info = [function, " has implicit default visibility\n"]
                    results.append(self.generate_result(info))
        return results
class DonationAttackDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-donation-attack'
    HELP = 'Donation Attack / Vault Inflation (SC-117)'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://example.com/donation-attack"
    WIKI_TITLE = "Donation Attack"
    WIKI_DESCRIPTION = "Vault share minting may be manipulable by pre-deposit donation/inflation patterns."
    WIKI_EXPLOIT_SCENARIO = "An attacker sends tokens directly to the vault to inflate the exchange rate."
    WIKI_RECOMMENDATION = "Use ERC-4626 anti-inflation controls and minimum share mint thresholds."

    def _detect(self):
        results = []
        for contract in self.contracts:
            has_vault_calc = False
            has_donation = False
            vuln_funcs = []
            
            for function in contract.functions_and_modifiers:
                name_lower = function.name.lower()
                if any(x in name_lower for x in ['totalassets', 'converttoshares', 'previewdeposit']):
                    has_vault_calc = True
                    vuln_funcs.append(function)
                if any(x in name_lower for x in ['donate', 'skim', 'first_depositor', 'firstdepositor']):
                    has_donation = True
                    vuln_funcs.append(function)
            
            if has_vault_calc and has_donation:
                self.guardian_findings.append(contract.name)
                # Just report the first matching function as the locus
                info = [vuln_funcs[0], " implements vault logic and donation vector which allows vault inflation\\n"]
                results.append(self.generate_result(info))
        return results

class MissingEventDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-missing-event'
    HELP = 'Missing Event Emission on State Change (SC-121)'
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/missing-event"
    WIKI_TITLE = "Missing Event Emission"
    WIKI_DESCRIPTION = "Critical state-changing functions do not emit auditable events."
    WIKI_EXPLOIT_SCENARIO = "Admin changes ownership but no event is emitted, leaving monitoring systems blind."
    WIKI_RECOMMENDATION = "Emit events for all privileged state-changing operations."

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                if function.is_constructor or function.view or function.pure:
                    continue
                # Structural: functions that write any address-typed state variable
                address_writes = []
                for node in function.nodes:
                    for sv in node.state_variables_written:
                        if str(sv.type) == 'address':
                            address_writes.append(sv.name)
                if not address_writes:
                    continue
                # Check for emit statement in function body
                source_code = function.source_mapping.content if function.source_mapping else ""
                if 'emit ' not in source_code:
                    self.guardian_findings.append(contract.name)
                    info = [function, " changes address state variable without emitting event\n"]
                    results.append(self.generate_result(info))
        return results

class RewardRoundingDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-reward-rounding'
    HELP = 'Reward Distribution Rounding (SC-124)'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/reward-rounding"
    WIKI_TITLE = "Reward Rounding"
    WIKI_DESCRIPTION = "Integer division in reward accounting without scaling causes systematic dust loss."
    WIKI_EXPLOIT_SCENARIO = "Small stakers lose dust on every reward calculation epoch."
    WIKI_RECOMMENDATION = "Multiply by 1e18 or a PRECISION constant before dividing to preserve fixed-point accuracy."

    # Scaling indicators — if present in function source, it is safe (scaled before dividing)
    _SCALING = re.compile(
        r'\*\s*(1[eE]\d+|10\*\*\d+|PRECISION|WAD|SCALE|FixedPoint|RAY)\b',
        re.IGNORECASE
    )

    def _detect(self):
        from slither.slithir.operations import Binary, BinaryType
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                source_code = function.source_mapping.content if function.source_mapping else ""
                # If the function source contains any scaling multiplier it is safe
                if self._SCALING.search(source_code):
                    continue
                # Look for IR-level division where the divisor is a state variable
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type != BinaryType.DIVISION:
                            continue
                        # Divisor must be a state variable (not a constant or local)
                        divisor = ir.variable_right
                        is_state = any(sv.name == getattr(divisor, 'name', '') for sv in contract.state_variables)
                        if is_state:
                            self.guardian_findings.append(function.name)
                            info = [node, " divides by state variable without scaling\n"]
                            results.append(self.generate_result(info))
                            break
                    else:
                        continue
                    break  # one finding per function
        return results

class PermitPhishingDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-permit-phishing'
    HELP = 'Permit Phishing Vector (SC-123)'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/permit-phishing"
    WIKI_TITLE = "Permit Phishing"
    WIKI_DESCRIPTION = "Permit-style functions without domain separation allow cross-protocol signature replay."
    WIKI_EXPLOIT_SCENARIO = "Attacker replays a valid permit signature on a different contract."
    WIKI_RECOMMENDATION = "Validate DOMAIN_SEPARATOR and EIP-712 encoding in all permit-style functions."

    # Signature: v/r/s params indicate an off-chain signature flow
    _VRS_PARAMS = re.compile(r'\bv\b.*\br\b.*\bs\b', re.DOTALL)

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                source_code = function.source_mapping.content if function.source_mapping else ""
                # Identify permit-style functions: 'permit' in name OR v/r/s params present
                name_lower = function.name.lower()
                has_vrs = self._VRS_PARAMS.search(source_code[:source_code.find('{')]) if '{' in source_code else False
                is_permit_like = 'permit' in name_lower or has_vrs
                if not is_permit_like:
                    continue
                # Safe if it validates DOMAIN_SEPARATOR or EIP712 inside the body
                body = source_code[source_code.find('{'):] if '{' in source_code else source_code
                has_domain_check = ('DOMAIN_SEPARATOR' in body or 'EIP712' in body or
                                    'domainSeparator' in body or '_hashTypedDataV4' in body)
                if not has_domain_check:
                    self.guardian_findings.append(contract.name)
                    info = [function, " permit-style function lacks DOMAIN_SEPARATOR/EIP-712 validation\n"]
                    results.append(self.generate_result(info))
        return results

class MissingZeroAddressDetector(GuardianAbstractDetector):
    ARGUMENT = 'guardian-missing-zero'
    HELP = 'Missing Zero-Address Check (SC-118)'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://example.com/missing-zero"
    WIKI_TITLE = "Missing Zero-Address Check"
    WIKI_DESCRIPTION = "Sensitive address assignments may not reject `address(0)`."
    WIKI_EXPLOIT_SCENARIO = "An admin calls any function that sets an address state var to address(0), bricking the contract."
    WIKI_RECOMMENDATION = "Add explicit `require(target != address(0))` checks."

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                # Skip constructors and read-only functions
                if function.is_constructor or function.view or function.pure:
                    continue

                # Structural check: find functions that write any address-typed state variable
                address_writes = []
                for node in function.nodes:
                    for sv in node.state_variables_written:
                        if str(sv.type) == 'address':
                            address_writes.append(sv.name)

                if address_writes:
                    source_code = function.source_mapping.content if function.source_mapping else ""
                    # Flag if no zero-address guard is present anywhere in the function body
                    if "address(0)" not in source_code and "0x0" not in source_code.replace(" ", ""):
                        self.guardian_findings.append(contract.name)
                        info = [function, " assigns to address state variable without zero-address check\n"]
                        results.append(self.generate_result(info))
        return results

CUSTOM_DETECTORS = [
    AccessControlDetector,
    UnprotectedInitializeDetector,
    UncappedMintDetector,
    FlashLoanAttackDetector,
    SignatureReplayDetector,
    GovernanceAttackDetector,
    MEVSandwichDetector,
    NoTimelockDetector,
    OracleCentralizationDetector,
    ReentrancyDetector,
    SC002Detector,
    SC010Detector,
    SC011Detector,
    SC061Detector,
    SC100Detector,
    SC103Detector,
    SC104Detector,
    SC106Detector,
    SC107Detector,
    SC110Detector,
    DelegatecallDetector,
    IntegerOverflowDetector,
    TxOriginDetector,
    SelfdestructDetector,
    TimestampDetector,
    UnverifiedProxyDetector,
    ReadOnlyReentrancyDetector,
    StorageCollisionDetector,
    MissingDeadlineDetector,
    UncheckedArithmeticDetector,
    DefaultVisibilityDetector,
    DonationAttackDetector,
    MissingEventDetector,
    RewardRoundingDetector,
    PermitPhishingDetector,
    MissingZeroAddressDetector
]
