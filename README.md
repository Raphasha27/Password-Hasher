<div align="center">

# Password Hasher

**Password hashing utility comparing bcrypt, Argon2, and PBKDF2 with detailed security reporting**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Focused-FF4500?style=for-the-badge)](SECURITY.md)

[![Kirov Dynamics](https://img.shields.io/badge/Part_of-Kirov_Dynamics-0EA5E9?style=for-the-badge)](https://github.com/Raphasha27/kirov-dynamics)

**Built by [Koketso Raphasha](https://github.com/Raphasha27) — Practical AI for Africa**

</div>

## Overview

Production-ready password hashing utility that implements and compares the three industry-standard hashing algorithms: bcrypt, Argon2id, and PBKDF2-SHA256. Generates detailed security reports with benchmark comparisons and migration recommendations.

## Features

- **bcrypt Hashing** — Cost-factor configurable, salt auto-generation
- **Argon2id Hashing** — Memory, time, and parallelism parameters
- **PBKDF2-SHA256** — Iteration-count configurable
- **Algorithm Comparison** — Speed, security, and memory usage benchmarks
- **Security Reports** — Detailed recommendations for production use
- **Verification** — Password verification against stored hashes

## Quick Start

```bash
git clone https://github.com/Raphasha27/Password-Hasher.git
cd Password-Hasher
pip install -r requirements.txt
python hasher.py --password "YourPasswordHere" --algorithm argon2
```

## Ecosystem

| Project | Description |
|---------|-------------|
| [Password-Analyzer](https://github.com/Raphasha27/Password-Analyzer) | Entropy calculation and NIST strength scoring |
| [Suspicious-URL-Checker](https://github.com/Raphasha27/Suspicious-URL-Checker) | Phishing URL detection and risk scoring |

## Product Ladder

```
GitHub (this repo)
    ↓
Portfolio → https://raphasha27.github.io/raphasha-dev-portfolio
    ↓
Contact → https://github.com/Raphasha27
```

## License

MIT — see [LICENSE](LICENSE)
