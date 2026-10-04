// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";

interface IGuardianPassportRegistry {
    function isPassportActive(bytes32 agentId) external view returns (bool);
}

interface IGuardianThreatOracle {
    function isFlagged(address account) external view returns (bool);
}

/**
 * @title GuardianAgentWallet
 * @notice A contract wallet for an AI agent. The agent's funds live here, not in the agent's key.
 *
 *         Moving anything out needs TWO independent things in the same call:
 *           1. the agent's own key (msg.sender == operator), and
 *           2. a fresh EIP-712 SafetyAttestation signed by GuardianAI for this exact
 *              target, value and calldata, bound to this wallet (EIP-712 domain) and this agent.
 *
 *         If a GuardianThreatOracle is set (the scam list written by a Chainlink CRE workflow), the call
 *         target and the token recipient/spender are checked against it on-chain as well.
 *
 *         So an agent that skips GuardianAI and sends a transaction straight to Monad RPC is
 *         refused by the chain, and a stolen GuardianAI signer key alone cannot move funds either.
 *
 * @dev    The wallet never grants token allowances to a shared spender, so one agent's approval
 *         can never be used to pull another agent's funds. It deliberately does NOT implement
 *         ERC-1271, so it cannot sign off-chain approvals (Permit/Permit2 orders) that would move
 *         funds without an attestation.
 *
 *         The owner (the human) keeps an emergency path (ownerExecute) and the admin controls.
 *         The owner key should be a passkey, hardware wallet, multisig or timelock.
 */
contract GuardianAgentWallet is EIP712, Ownable2Step, Pausable, ReentrancyGuard, ERC721Holder, ERC1155Holder {

    struct SafetyAttestation {
        bytes32 agentId;
        address targetContract;
        bytes32 calldataHash;
        uint256 value;
        uint8 riskScore;
        uint256 nonce;
        uint256 deadline;
    }

    /// @dev Same struct and type string as GuardianPolicyGuard, so the relay signs both with one code path.
    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "SafetyAttestation(bytes32 agentId,address targetContract,bytes32 calldataHash,uint256 value,uint8 riskScore,uint256 nonce,uint256 deadline)"
    );

    /// @notice keccak256 of the agent's GuardianAI agent_id string. Fixed for the wallet's lifetime.
    bytes32 public immutable agentId;
    /// @notice The agent's hot key (e.g. a Privy server wallet). Can request execution, cannot act alone.
    address public operator;
    /// @notice GuardianAI's attestation signer.
    address public guardianSigner;
    /// @notice Optional GuardianPassportSBT; when set, a revoked ID card freezes the wallet.
    address public passportRegistry;
    /// @notice Optional GuardianThreatOracle (Chainlink CRE). When set, flagged destinations are refused on-chain.
    address public threatOracle;
    uint8 public maxAllowedRiskScore = 25;

    mapping(uint256 => bool) public usedNonces;

    event Executed(uint256 indexed nonce, address indexed target, uint256 value, uint8 riskScore, bytes32 calldataHash);
    event OwnerExecuted(address indexed target, uint256 value, bytes32 calldataHash);
    event Deposited(address indexed from, uint256 value);
    event NonceCancelled(uint256 indexed nonce);
    event OperatorUpdated(address indexed previousOperator, address indexed newOperator);
    event GuardianSignerUpdated(address indexed previousSigner, address indexed newSigner);
    event PassportRegistryUpdated(address indexed previousRegistry, address indexed newRegistry);
    event MaxAllowedRiskScoreUpdated(uint8 previousScore, uint8 newScore);
    event ThreatOracleUpdated(address indexed previousOracle, address indexed newOracle);

    error NotOperator(address caller);
    error NotOperatorOrOwner(address caller);
    error ZeroAddress();
    error InvalidTarget();
    error AgentMismatch(bytes32 expected, bytes32 actual);
    error TargetMismatch(address expected, address actual);
    error ValueMismatch(uint256 expected, uint256 actual);
    error CalldataHashMismatch();
    error AttestationExpired(uint256 deadline, uint256 nowTs);
    error RiskScoreExceedsThreshold(uint8 riskScore, uint8 maxAllowed);
    error PassportRevokedOrInactive(bytes32 agentId);
    error InvalidAttestationSignature();
    error NonceAlreadyUsed(uint256 nonce);
    error InvalidRiskThreshold(uint8 value);
    error CallFailed();
    error FlaggedDestination(address account);

    constructor(
        address owner_,
        address operator_,
        address guardianSigner_,
        bytes32 agentId_,
        address passportRegistry_
    ) EIP712("GuardianAgentWallet", "1") Ownable(owner_) {
        if (operator_ == address(0) || guardianSigner_ == address(0)) revert ZeroAddress();
        operator = operator_;
        guardianSigner = guardianSigner_;
        agentId = agentId_;
        passportRegistry = passportRegistry_;
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    // ── Agent path: operator key + GuardianAI attestation ─────────────────

    /**
     * @notice Run one call approved by GuardianAI. Value comes from the wallet's own balance.
     * @param target   Contract (or, for a plain MON transfer with empty data, any address) to call.
     * @param value    Native MON to send, taken from this wallet.
     * @param data     Calldata. Its keccak256 must equal attestation.calldataHash.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        SafetyAttestation calldata attestation,
        bytes calldata signature
    ) external nonReentrant whenNotPaused returns (bytes memory) {
        if (msg.sender != operator) revert NotOperator(msg.sender);
        if (attestation.agentId != agentId) revert AgentMismatch(agentId, attestation.agentId);
        if (target == address(0) || target == address(this)) revert InvalidTarget();
        if (target != attestation.targetContract) revert TargetMismatch(attestation.targetContract, target);
        if (value != attestation.value) revert ValueMismatch(attestation.value, value);
        if (keccak256(data) != attestation.calldataHash) revert CalldataHashMismatch();
        if (block.timestamp > attestation.deadline) revert AttestationExpired(attestation.deadline, block.timestamp);
        if (attestation.riskScore > maxAllowedRiskScore)
            revert RiskScoreExceedsThreshold(attestation.riskScore, maxAllowedRiskScore);
        if (passportRegistry != address(0) && !IGuardianPassportRegistry(passportRegistry).isPassportActive(agentId))
            revert PassportRevokedOrInactive(agentId);

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            attestation.agentId,
            attestation.targetContract,
            attestation.calldataHash,
            attestation.value,
            attestation.riskScore,
            attestation.nonce,
            attestation.deadline
        )));
        if (ECDSA.recover(digest, signature) != guardianSigner) revert InvalidAttestationSignature();

        if (usedNonces[attestation.nonce]) revert NonceAlreadyUsed(attestation.nonce);
        usedNonces[attestation.nonce] = true;

        // Calldata to an address with no code would silently "succeed": refuse it.
        if (data.length > 0 && target.code.length == 0) revert InvalidTarget();

        if (threatOracle != address(0)) _checkDestinations(target, data);

        bytes memory ret = _call(target, value, data);
        emit Executed(attestation.nonce, target, value, attestation.riskScore, attestation.calldataHash);
        return ret;
    }

    /// @notice Agent kill switch: the operator (or owner) can freeze the wallet. Only the owner can unfreeze.
    function pause() external {
        if (msg.sender != operator && msg.sender != owner()) revert NotOperatorOrOwner(msg.sender);
        _pause();
    }

    // ── Human path ────────────────────────────────────────────────────────

    /// @notice Emergency/administrative call by the human owner. No attestation needed. Works while paused.
    function ownerExecute(address target, uint256 value, bytes calldata data)
        external
        onlyOwner
        nonReentrant
        returns (bytes memory)
    {
        if (target == address(0) || target == address(this)) revert InvalidTarget();
        bytes memory ret = _call(target, value, data);
        emit OwnerExecuted(target, value, keccak256(data));
        return ret;
    }

    function unpause() external onlyOwner { _unpause(); }

    /// @notice Burn an attestation nonce so an already-issued approval can never be used.
    function cancelNonce(uint256 nonce) external {
        if (msg.sender != operator && msg.sender != owner()) revert NotOperatorOrOwner(msg.sender);
        usedNonces[nonce] = true;
        emit NonceCancelled(nonce);
    }

    function setOperator(address newOperator) external onlyOwner {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorUpdated(operator, newOperator);
        operator = newOperator;
    }

    function setGuardianSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        emit GuardianSignerUpdated(guardianSigner, newSigner);
        guardianSigner = newSigner;
    }

    function setPassportRegistry(address registry) external onlyOwner {
        emit PassportRegistryUpdated(passportRegistry, registry);
        passportRegistry = registry;
    }

    function setThreatOracle(address oracle) external onlyOwner {
        emit ThreatOracleUpdated(threatOracle, oracle);
        threatOracle = oracle;
    }

    function setMaxAllowedRiskScore(uint8 newMax) external onlyOwner {
        if (newMax > 100) revert InvalidRiskThreshold(newMax);
        emit MaxAllowedRiskScoreUpdated(maxAllowedRiskScore, newMax);
        maxAllowedRiskScore = newMax;
    }

    /// @notice EIP-712 domain separator the relay must sign against (name "GuardianAgentWallet", version "1").
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ── Internal ──────────────────────────────────────────────────────────

    /// @dev Refuse if the call target, or the token recipient / spender / operator in the calldata, is flagged.
    function _checkDestinations(address target, bytes calldata data) private view {
        IGuardianThreatOracle oracle = IGuardianThreatOracle(threatOracle);
        if (oracle.isFlagged(target)) revert FlaggedDestination(target);
        if (data.length < 4) return;
        bytes4 sel = bytes4(data[:4]);
        uint256 argIndex;
        if (
            sel == 0xa9059cbb || // transfer(to,amount)
            sel == 0x095ea7b3 || // approve(spender,amount)
            sel == 0x39509351 || // increaseAllowance(spender,amount)
            sel == 0xa22cb465    // setApprovalForAll(operator,bool)
        ) {
            argIndex = 0;
        } else if (
            sel == 0x23b872dd || // transferFrom(from,to,amount|id)
            sel == 0x42842e0e || // safeTransferFrom(from,to,id)
            sel == 0xb88d4fde || // safeTransferFrom(from,to,id,data)
            sel == 0xf242432a || // ERC-1155 safeTransferFrom(from,to,id,amount,data)
            sel == 0x2eb2c2d6    // ERC-1155 safeBatchTransferFrom(from,to,ids,amounts,data)
        ) {
            argIndex = 1;
        } else {
            return;
        }
        uint256 start = 4 + 32 * argIndex;
        if (data.length < start + 32) return;
        address dest = address(uint160(uint256(bytes32(data[start:start + 32]))));
        if (oracle.isFlagged(dest)) revert FlaggedDestination(dest);
    }

    function _call(address target, uint256 value, bytes calldata data) private returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            if (ret.length > 0) {
                assembly { revert(add(32, ret), mload(ret)) }
            }
            revert CallFailed();
        }
        return ret;
    }
}
