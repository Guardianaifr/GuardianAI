// Safe: block.timestamp used only for a cosmetic UI decision (theme selection).
// No state writes, no external calls, declared as view — purely display use.
// SC-050 must NOT flag this.
function getTheme() external view returns (string memory) {
    if (block.timestamp % 2 == 0) return "dark";
    return "light";
}