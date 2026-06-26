# 🛡️ GuardianAI — Crypto Security Audit Platform

## Vision
**GuardianAI becomes the CertiK for AI-powered crypto projects.**

Every Web3 project using AI agents (trading bots, dating games, NFT generators, DeFi yield optimizers, autonomous DAOs) needs an AI security audit before launch. GuardianAI provides that audit — automated, instant, and backed by real exploit evidence.

---

## Phase 1: Automated Multi-Target Scanner (Build Now)
> Goal: Any user pastes a URL → gets a full security report in 60 seconds

### What We Build
| Component | Purpose |
|-----------|---------|
| **URL Scanner Engine** | Crawl any website, detect AI/LLM integration points automatically |
| **API Mapper** | Auto-discover `/api/*`, `/v1/chat/*`, WebSocket endpoints |
| **Attack Suite** | 6 attack categories × 10+ vectors each = 60+ total vectors |
| **Report Generator** | Branded PDF per target with before/after metrics |
| **Self-Service Portal** | Web form: paste URL → get report → pay for detailed version |

### Attack Categories (6 Pillars)
```
┌─────────────────────────────────────────────────────────┐
│                 GUARDIANAI AUDIT FRAMEWORK               │
├─────────────┬───────────────────────────────────────────┤
│ PILLAR 1    │ Prompt Injection & Jailbreak              │
│             │ - Direct injection, indirect injection,   │
│             │   multi-turn, encoding attacks            │
├─────────────┼───────────────────────────────────────────┤
│ PILLAR 2    │ Data Exfiltration & Privacy               │
│             │ - System prompt leakage, PII extraction,  │
│             │   training data extraction                │
├─────────────┼───────────────────────────────────────────┤
│ PILLAR 3    │ Smart Contract Manipulation               │
│             │ - AI-to-contract hallucination,           │
│             │   oracle spoofing, ABI injection          │
├─────────────┼───────────────────────────────────────────┤
│ PILLAR 4    │ Multi-Agent Exploitation                  │
│             │ - Cross-agent infection, context           │
│             │   poisoning, agent impersonation          │
├─────────────┼───────────────────────────────────────────┤
│ PILLAR 5    │ Financial Logic Manipulation              │
│             │ - Betting outcome rigging, yield          │
│             │   manipulation, MEV via prompt            │
├─────────────┼───────────────────────────────────────────┤
│ PILLAR 6    │ Infrastructure & API Security             │
│             │ - Rate limiting, auth bypass, CORS,       │
│             │   WebSocket hijacking, DoS               │
└─────────────┴───────────────────────────────────────────┘
```

### Target Project Types We Cover
| Project Type | Example | Key Risk |
|-------------|---------|----------|
| AI Dating/Betting | AgentLove | Rigged outcomes steal tokens |
| AI Trading Bots | Fetch.ai, Autonolas | Unauthorized trades drain wallets |
| AI NFT Generators | Artblocks AI | Prompt injection creates offensive content |
| DeFi Yield Agents | Yearn v3 AI | Agent drains liquidity pools |
| AI DAOs | AI16z | Governance manipulation via prompt |
| AI Chatbots on-chain | Freysa, MyShell | Direct fund theft via injection |
| AI Oracles | Chainlink Functions | Data poisoning affects all downstream contracts |

---

## Phase 2: Self-Service Audit Portal (Build Next)
> Goal: Projects can audit themselves on guardianai.com

### User Flow
```
1. User visits guardianai.com/audit
2. Pastes their API endpoint URL
3. Selects scan depth (Quick / Standard / Deep)
4. GuardianAI runs 60+ attack vectors
5. Real-time progress shown on dashboard
6. Report generated with:
   - Security score (A+ to F)
   - OWASP LLM classification
   - Before/After GuardianAI comparison
   - Cryptographic badge (HMAC-signed)
   - SDK integration code
7. Free tier: Summary only
8. Paid tier: Full PDF + remediation code + badge
```

### Pricing Model
| Tier | Price | What They Get |
|------|-------|--------------|
| **Free Scan** | $0 | Security grade (A-F) + summary |
| **Standard Audit** | $299/scan | Full PDF report + OWASP mapping + remediation steps |
| **Enterprise** | $999/mo | Continuous monitoring + Slack/Discord alerts + badge |
| **White Glove** | $4,999 | Manual pen-test + custom report + SDK integration support |

---

## Phase 3: Public Trust Infrastructure (Build Later)
> Goal: "Audited by GuardianAI" becomes the trust standard

- **Public Badge Registry** — Verified badges on project websites
- **Leaderboard** — Top-scored AI projects ranked publicly  
- **Continuous Monitoring** — Re-scan every 24h, alert on regression
- **API for Wallets** — MetaMask/Rabby can check if a dApp is GuardianAI-certified before connecting

---

## What To Build RIGHT NOW

### Priority 1: Universal Site Scanner
Build a `CryptoAuditScanner` class that:
1. Takes any URL as input
2. Crawls the site for AI integration points
3. Runs the 6-pillar attack suite
4. Generates a branded PDF report
5. Signs a cryptographic badge

### Priority 2: Audit Portal Page
Add `/audit` page to the GuardianAI frontend where users can:
1. Paste a URL
2. See real-time scan progress
3. Download their report

### Priority 3: Landing Page Update
Update the main site to position as "AI Security for Crypto" not just "AI Firewall"
