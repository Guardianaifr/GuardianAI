import requests
import json
from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer

targets = [
    ("UniswapV2Pair", "https://raw.githubusercontent.com/Uniswap/v2-core/master/contracts/UniswapV2Pair.sol"),
    ("OpenZeppelin ERC20", "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/contracts/token/ERC20/ERC20.sol"),
    ("Uniswap Router02", "https://raw.githubusercontent.com/Uniswap/v2-periphery/master/contracts/UniswapV2Router02.sol"),
]

for name, url in targets:
    print()
    print("=" * 65)
    try:
        code = requests.get(url, timeout=10).text
    except Exception as e:
        print(f"FETCH FAILED: {name} — {e}")
        continue

    result = SmartContractAnalyzer(source_code=code, contract_name=name).analyze()

    print(f"CONTRACT : {name}")
    print(f"GRADE    : {result.grade}")
    print(f"SCORE    : {result.score}/100")
    print(f"VULNS    : {result.vulnerabilities_found}")
    print(f"SAFE     : {result.safe_checks}")
    print(f"RISK     : {json.dumps(result.risk_summary)}")

    if result.vulnerabilities:
        print()
        print("FINDINGS:")
        for v in result.vulnerabilities:
            sev = v.get("severity", "?").upper()
            rid = v.get("rule_id", "?")
            rname = v.get("name", "?")
            line = v.get("line", "?")
            compliance = v.get("compliance", {})
            soc2 = compliance.get("SOC-2", [])
            iso = compliance.get("ISO 27001", [])
            print(f"  [{sev:8}] {rid} - {rname}  (line {line})")
            if soc2:
                print(f"             SOC-2: {', '.join(soc2)}")
            if iso:
                print(f"             ISO:   {', '.join(iso)}")
    else:
        print("  No vulnerabilities detected.")

print()
print("=" * 65)
print("DONE")
