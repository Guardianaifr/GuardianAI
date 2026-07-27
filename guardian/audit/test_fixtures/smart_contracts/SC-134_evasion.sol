pragma solidity ^0.8.24;
// SC-134 evasion: uses 'transient' Solidity keyword instead of inline assembly tstore/tload.
// FIXTURE CORRECTION: old sstore-based evasion was mislabeled -- sstore is regular storage, not EIP-1153.
// Genuine evasion: transient storage declared with the Solidity 'transient' keyword (Dencun).
contract SC134_Evasion {
    uint transient lock;
    function set(uint v) public {
        lock = v;
    }
}
