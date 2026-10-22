# 🤝 Contributing to GuardianAI

Welcome! We are thrilled that you want to help make AI agents safer.

## 🚀 Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/<your-username>/GuardianAI.git
   cd GuardianAI
   ```
3. **Install Python dependencies** (Python 3.12):
   ```bash
   python3.12 -m venv .venv312
   source .venv312/bin/activate        # Windows: .\.venv312\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
4. **Run the Python tests** to ensure a healthy baseline:
   ```bash
   pytest
   ```

The JavaScript/TypeScript parts have their own `package.json` and tests (Node.js 22.23.4+, the October 2026
security release; `.nvmrc` pins it). Run `npm install && npm test` in the folder you change:

| Folder | What it is |
|---|---|
| `contracts/` | Solidity contracts (Hardhat: `npx hardhat test`) |
| `dashboard/` | Explorer and console (Vite + React, Vitest) |
| `metropolis/mera/` | Mera operator passkey (also `npm run test:hard`) |
| `metropolis/indexer/` | Envio indexer |
| `packages/guardian-middleware/` | Agent middleware SDK (ElizaOS, Viem) |
| `packages/eliza-host/` | Hosted ElizaOS agent |
| `packages/guardianai-eliza/` | One-command local ElizaOS CLI |

## 🛠️ Development Workflow

- **Branching**: Create a feature branch for your work (`git checkout -b feature/amazing-new-filter`).
- **Coding Standards**:
  - Follow PEP 8 for Python code.
  - Include PEP 257 docstrings for all new modules and classes.
  - Keep functions focused and well-tested.
- **Testing**: Add tests next to the code you change (`tests/` for Python, the package's own test folder for JS/TS).
- **Documentation**: Update `README.md` or the relevant doc in `docs/` if you change features, configuration, endpoints or test counts.
- **Secrets**: Never commit keys or `.env` files. CI's security gate (`tools/run_missing_security_validation.py`) includes a secret scan; `guardian/config/secret_scan_allowlist.txt` lists known false positives.

## 📝 Pull Request Process

1. Ensure all tests pass. CI (`.github/workflows/`) runs the Python security gate and supply-chain checks on every pull request, and the Hardhat suite when `contracts/` changes.
2. Note user-facing changes in [`docs/operations/RELEASE_NOTES.md`](docs/operations/RELEASE_NOTES.md).
3. Submit a Pull Request targeting the `main` branch.
4. Provide a clear description of the change and any related issues.
5. A maintainer will review your PR and provide feedback.

## ⚖️ Code of Conduct

Help us keep GuardianAI a welcoming and inclusive community. Be respectful, professional, and patient with others.

## 🆘 Questions?

If you have questions or need help, feel free to:
- Open a GitHub Issue.
- Check the [Troubleshooting Guide](docs/operations/TROUBLESHOOTING.md).
- Report security issues privately as described in [SECURITY.md](SECURITY.md), not in public issues.

Thank you for contributing!
