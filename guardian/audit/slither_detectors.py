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
    DelegatecallDetector,
    IntegerOverflowDetector,
    TxOriginDetector,
    SelfdestructDetector,
    TimestampDetector,
    UnverifiedProxyDetector,
    ReadOnlyReentrancyDetector,
    StorageCollisionDetector
]
