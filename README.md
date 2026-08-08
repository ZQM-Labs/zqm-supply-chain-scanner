# ZQM Supply Chain Scanner

Open-source supply-chain scanner for ZQM repos. Drop-in replacement for Snyk using only open-source tooling.

- Vulnerability detection via [OSV.dev](https://osv.dev) + `pip-audit` + `safety`
- License compliance enforcement
- Outdated package detection (PyPI, npm)
- SARIF output for GitHub Code Scanning / CodeQL
- GitHub PR/Security Advisory comments

## Usage

```bash
# Clone this repo into your project's CI
python snyk_replacement.py --repo owner/repo --output both --pr ${{ github.event.pull_request.number }}
```

## GitHub Action

```yaml
- uses: ZQM-Labs/zqm-supply-chain-scanner@main
  with:
    repo: ${{ github.repository }}
    pr: ${{ github.event.pull_request.number }}
```

## Supported ecosystems

- Python: `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`
- JavaScript: `package.json`, `package-lock.json`, `yarn.lock`
- Go: `go.mod`

## License allowlist

MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Python-2.0, Apache Software License, 0BSD

## Exit codes

- 0: clean or only low-severity findings
- 1: critical/high vulnerabilities, license violations, or `--fail-on` threshold exceeded
