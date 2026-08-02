// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title GuardianRiskAttestation
 * @notice Stores on-chain risk score attestations for audited smart contracts,
 *         providing verifiable security assessments that other DeFi protocols can query.
 *
 * @dev    Changes vs initial deployment:
 *
 *         RA-1 (Pausable): Added Pausable inheritance and whenNotPaused on attest(),
 *         matching the pattern used by the other 4 GuardianAI on-chain contracts.
 *         The only call path (cortex_routes.py risk_attest_onchain) is an admin-only
 *         HTTP endpoint that already wraps the call in try/except → HTTP 400, so a
 *         paused revert surfaces gracefully rather than silently.
 *
 *         RA-3 (Grade allowlist): Replaced the non-empty string check with a
 *         configurable allowlist (_validGrades mapping, keyed by keccak256 of the
 *         grade string). Constructor bootstraps {A, B, C, D, F} — the exact 5 values
 *         produced by onchain_risk_scorer._grade(). Owner can extend the allowlist
 *         via setValidGrade() without redeployment, accommodating the broader 9-value
 *         Grade enum (A+, A, A-, B+, B, B-, C, D, F) already present in
 *         guardian/audit/models.py and the extra "C+" produced by crypto_scanner.py.
 *
 *         RA-4 (Silent overwrite): Previously, re-attesting an already-attested
 *         contract emitted only RiskAttested, indistinguishable from a first
 *         attestation. Now a separate AttestationUpdated event is emitted on overwrite
 *         so on-chain indexers can distinguish creation from update without off-chain
 *         state tracking.
 */
contract GuardianRiskAttestation is Ownable2Step, Pausable {

    // ── Types ────────────────────────────────────────────────────────────

    struct Attestation {
        uint16  score;           // 0–10000 (e.g. 9500 = 95.00%)
        string  grade;           // e.g. "A", "B+", "F"
        bytes32 signalsHash;     // keccak256 of the full signals JSON/metadata
        uint256 attestedAt;
        uint256 blockNumber;
    }

    // ── State ────────────────────────────────────────────────────────────

    /// @notice contractAddress => chain => Attestation
    mapping(address => mapping(string => Attestation)) public attestations;

    /// @notice Total number of unique (contractAddress, chain) pairs ever attested
    uint256 public totalAttestations;

    /// @dev Valid grade strings, keyed by keccak256(abi.encodePacked(grade)).
    ///      Bootstrapped in the constructor; extensible via setValidGrade().
    mapping(bytes32 => bool) private _validGrades;

    // ── Events ───────────────────────────────────────────────────────────

    /// @notice Emitted when a new (contractAddress, chain) pair is attested for the first time.
    event RiskAttested(
        address indexed contractAddress,
        string  indexed chain,
        uint16          score,
        string          grade,
        bytes32         signalsHash
    );

    /// @notice Emitted when an existing attestation is overwritten.
    ///         Distinct from RiskAttested so indexers can track updates vs. creations.
    event AttestationUpdated(
        address indexed contractAddress,
        string  indexed chain,
        uint16          score,
        string          grade,
        bytes32         signalsHash
    );

    /// @notice Emitted when the grade allowlist is changed.
    event ValidGradeSet(string grade, bool allowed);

    // ── Errors ───────────────────────────────────────────────────────────

    error InvalidScore();
    /// @notice grade is not in the on-chain allowlist. Use setValidGrade() to extend.
    error GradeNotAllowed(string grade);
    error AttestationNotFound();
    error InvalidGradeLength();

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {
        // Bootstrap with the 5 grades currently produced by onchain_risk_scorer._grade():
        //   score >= 90 → "A", >= 80 → "B", >= 70 → "C", >= 60 → "D", else → "F"
        // The broader 9-value Grade enum in guardian/audit/models.py (A+, A, A-, B+, B,
        // B-, C, D, F) can be enabled by the owner via setValidGrade() without redeployment.
        _validGrades[keccak256(bytes("A"))] = true;
        _validGrades[keccak256(bytes("B"))] = true;
        _validGrades[keccak256(bytes("C"))] = true;
        _validGrades[keccak256(bytes("D"))] = true;
        _validGrades[keccak256(bytes("F"))] = true;
    }

    // ── Write functions ──────────────────────────────────────────────────

    /**
     * @notice Attest to a smart contract's risk score and security grade.
     * @param _contractAddress The contract being audited.
     * @param _chain           The chain name (e.g. "ethereum", "monad").
     * @param _score           The risk score (0–10000).
     * @param _grade           The letter grade — must be in the _validGrades allowlist.
     * @param _signalsHash     keccak256 hash of the audit signals JSON.
     *
     * @dev  Emits RiskAttested on first attestation for a (contract, chain) pair, or
     *       AttestationUpdated when overwriting an existing attestation (RA-4).
     */
    function attest(
        address        _contractAddress,
        string calldata _chain,
        uint16          _score,
        string calldata _grade,
        bytes32         _signalsHash
    ) external onlyOwner whenNotPaused {
        require(_contractAddress != address(0), "Invalid contract address");
        require(bytes(_chain).length > 0, "Invalid chain string");
        if (_score > 10000) revert InvalidScore();
        if (!_validGrades[keccak256(bytes(_grade))]) revert GradeNotAllowed(_grade);

        bool isNew = attestations[_contractAddress][_chain].attestedAt == 0;
        if (isNew) {
            totalAttestations++;
        }

        attestations[_contractAddress][_chain] = Attestation({
            score:       _score,
            grade:       _grade,
            signalsHash: _signalsHash,
            attestedAt:  block.timestamp,
            blockNumber: block.number
        });

        if (isNew) {
            emit RiskAttested(_contractAddress, _chain, _score, _grade, _signalsHash);
        } else {
            emit AttestationUpdated(_contractAddress, _chain, _score, _grade, _signalsHash);
        }
    }

    /**
     * @notice Add or remove a grade string from the allowlist.
     * @param grade   The grade string (1–3 bytes, e.g. "A", "B+", "A-").
     * @param allowed true to allow, false to revoke.
     * @dev   Use this to extend the allowlist when onchain_risk_scorer._grade() is
     *        updated to output finer-grained grades (A+, A-, B+, B-, C+, etc.).
     */
    function setValidGrade(string calldata grade, bool allowed) external onlyOwner {
        uint256 len = bytes(grade).length;
        if (len == 0 || len > 3) revert InvalidGradeLength();
        _validGrades[keccak256(bytes(grade))] = allowed;
        emit ValidGradeSet(grade, allowed);
    }

    // ── Read functions ───────────────────────────────────────────────────

    /**
     * @notice Check whether a grade string is in the current allowlist.
     */
    function isValidGrade(string calldata grade) external view returns (bool) {
        return _validGrades[keccak256(bytes(grade))];
    }

    /**
     * @notice Get the latest attestation for a contract on a specific chain.
     */
    function getAttestation(address _contractAddress, string calldata _chain)
        external
        view
        returns (Attestation memory)
    {
        Attestation memory att = attestations[_contractAddress][_chain];
        if (att.attestedAt == 0) revert AttestationNotFound();
        return att;
    }

    // ── Admin/Pausable functions ─────────────────────────────────────────

    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
