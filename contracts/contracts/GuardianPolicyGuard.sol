// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title GuardianPolicyGuard
 * @notice Validates cryptographic EIP-712 safety attestations signed off-chain
 *         by GuardianAI before permitting transactions to execute on Monad.
 * @dev Enforces strict expiry, non-reentrant execution, value integrity, and
 *      agent-namespaced replay protection optimized for Monad parallel execution.
 */
contract GuardianPolicyGuard is EIP712, Ownable2Step, Pausable, ReentrancyGuard {

    // ── Structs ───────────────────────────────────────────────────────────

    struct SafetyAttestation {
        bytes32 agentId;
        address targetContract;
        bytes32 calldataHash;
        uint256 value;
        uint8 riskScore;       // 0-100 scale (0-25 = Safe, >25 = High Risk)
        uint256 nonce;         // Agent-namespaced unordered nonce
        uint256 deadline;      // Unix timestamp TTL
    }

    // ── Constants ─────────────────────────────────────────────────────────

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "SafetyAttestation(bytes32 agentId,address targetContract,bytes32 calldataHash,uint256 value,uint8 riskScore,uint256 nonce,uint256 deadline)"
    );

    // ── State Variables ───────────────────────────────────────────────────

    address public attestationSigner;
    uint8 public maxAllowedRiskScore = 25; // Default safety threshold

    /// @notice agentId => nonce => isUsed (Namespaced for Monad parallel execution)
    mapping(bytes32 => mapping(uint256 => bool)) public usedNonces;

    // ── Events ────────────────────────────────────────────────────────────

    event ActionExecutedWithAttestation(
        bytes32 indexed agentId,
        address indexed target,
        uint8 riskScore,
        uint256 nonce
    );
    event AttestationSignerUpdated(address indexed previousSigner, address indexed newSigner);
    event MaxAllowedRiskScoreUpdated(uint8 previousScore, uint8 newScore);

    // ── Custom Errors ─────────────────────────────────────────────────────

    error InvalidTargetAddress();
    error SelfCallProhibited();
    error InvalidSignerAddress();
    error ValueMismatch(uint256 expected, uint256 actual);
    error AttestationExpired(uint256 deadline, uint256 currentTimestamp);
    error RiskScoreExceedsThreshold(uint8 riskScore, uint8 maxAllowed);
    error NonceAlreadyUsed(bytes32 agentId, uint256 nonce);
    error TargetMismatch(address expectedTarget, address actualTarget);
    error CalldataHashMismatch();
    error InvalidAttestationSignature();
    error TargetCallFailed();
    error SweepFailed();

    // ── Constructor ───────────────────────────────────────────────────────

    constructor(address _signer)
        Ownable(msg.sender)
        EIP712("GuardianPolicyGuard", "1")
    {
        if (_signer == address(0)) revert InvalidSignerAddress();
        attestationSigner = _signer;
    }

    // ── External Execution ────────────────────────────────────────────────

    /**
     * @notice Executes a transaction on a target contract after verifying an EIP-712 safety attestation.
     * @param target The target contract address to execute against.
     * @param data The calldata payload to execute on the target.
     * @param attestation The typed safety attestation signed by the authorized Guardian relayer.
     * @param signature The EIP-712 cryptographic signature over the attestation.
     * @return returnData The raw bytes returned by the target call.
     */
    function executeWithAttestation(
        address target,
        bytes calldata data,
        SafetyAttestation calldata attestation,
        bytes calldata signature
    ) external payable nonReentrant whenNotPaused returns (bytes memory) {
        // 1. Target address integrity (Audit M-02)
        if (target == address(0)) revert InvalidTargetAddress();
        if (target == address(this)) revert SelfCallProhibited();
        if (target != attestation.targetContract) revert TargetMismatch(attestation.targetContract, target);

        // 2. Value integrity (Audit M-01)
        if (msg.value != attestation.value) revert ValueMismatch(attestation.value, msg.value);

        // 3. Calldata integrity
        if (keccak256(data) != attestation.calldataHash) revert CalldataHashMismatch();

        // 4. Expiry & Risk validation
        if (block.timestamp > attestation.deadline)
            revert AttestationExpired(attestation.deadline, block.timestamp);
        if (attestation.riskScore > maxAllowedRiskScore)
            revert RiskScoreExceedsThreshold(attestation.riskScore, maxAllowedRiskScore);

        // 5. Cryptographic EIP-712 signature verification (Audit M-02-R2: Before nonce write)
        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                attestation.agentId,
                attestation.targetContract,
                attestation.calldataHash,
                attestation.value,
                attestation.riskScore,
                attestation.nonce,
                attestation.deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address recoveredSigner = ECDSA.recover(digest, signature);
        if (recoveredSigner != attestationSigner) revert InvalidAttestationSignature();

        // 6. Replay protection — written AFTER signature is confirmed valid (Audit M-02-R2)
        if (usedNonces[attestation.agentId][attestation.nonce])
            revert NonceAlreadyUsed(attestation.agentId, attestation.nonce);
        usedNonces[attestation.agentId][attestation.nonce] = true;

        // 7. Target must be a contract, not an EOA (prevents silent fund loss)
        if (target.code.length == 0) revert InvalidTargetAddress();

        // 8. External call with revert bubbling (Audit L-01)
        (bool success, bytes memory returnData) = target.call{value: msg.value}(data);
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returndata_size := mload(returnData)
                    revert(add(32, returnData), returndata_size)
                }
            } else {
                revert TargetCallFailed();
            }
        }

        emit ActionExecutedWithAttestation(
            attestation.agentId, target, attestation.riskScore, attestation.nonce
        );
        return returnData;
    }

    // ── Admin Functions ───────────────────────────────────────────────────

    /**
     * @notice Set a new authorized attestation signer.
     * @param newSigner The address of the new signer.
     */
    function setAttestationSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert InvalidSignerAddress();
        emit AttestationSignerUpdated(attestationSigner, newSigner);
        attestationSigner = newSigner;
    }

    /**
     * @notice Set the maximum allowed risk score for attestations.
     * @param newMaxRisk The new maximum risk score.
     */
    function setMaxAllowedRiskScore(uint8 newMaxRisk) external onlyOwner {
        emit MaxAllowedRiskScoreUpdated(maxAllowedRiskScore, newMaxRisk);
        maxAllowedRiskScore = newMaxRisk;
    }

    /**
     * @notice Pause the contract.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpause the contract.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Sweeps accidentally sent ETH/MON to the specified address.
     * @param to The address to receive the swept funds.
     */
    function sweepETH(address payable to) external onlyOwner nonReentrant {
        if (to == address(0)) revert InvalidTargetAddress();
        (bool ok, ) = to.call{value: address(this).balance}("");
        if (!ok) revert SweepFailed();
    }
}