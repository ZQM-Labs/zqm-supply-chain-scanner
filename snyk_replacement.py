#!/usr/bin/env python3
"""
ZQM-Snyk-Replacement: open-source supply-chain scanner
- Scans Python/JS/Go dependencies for vulnerabilities (OSV)
- Checks license compliance
- Detects outdated packages
- Outputs GitHub Security Advisory comments + SARIF
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

# ── Config ──────────────────────────────────────────────────────────────
ECOSYSTEMS = {
    "python": ["requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile.lock"],
    "javascript": ["package.json", "package-lock.json", "yarn.lock"],
    "go": ["go.mod", "go.sum"],
}
ALLOWED_LICENSES = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Python-2.0", "Apache Software License", "0BSD"}
OSV_API = "https://api.osv.dev/v1/query"
GITHUB_API = "https://api.github.com"
MAX_RETRIES = 3
# ────────────────────────────────────────────────────────────────────────


def gh_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def api_post(url: str, payload: dict, headers: dict | None = None) -> dict:
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers=hdrs)
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = int(e.headers.get("Retry-After", 5))
                time.sleep(wait)
                continue
            return {"error": e.code, "body": e.read().decode()[:400]}
        except Exception as exc:
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
                continue
            return {"error": str(exc)[:200]}
    return {"error": "max retries exceeded"}


def api_get(url: str, headers: dict | None = None) -> dict:
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(int(e.headers.get("Retry-After", 5)))
                continue
            return {"error": e.code, "body": e.read().decode()[:400]}
        except Exception as exc:
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
                continue
            return {"error": str(exc)[:200]}
    return {"error": "max retries exceeded"}


# ── Dependency discovery ────────────────────────────────────────────────

def read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def parse_python_requirements(content: str) -> list[dict]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?(?:\s*[=<>!~\s]+\s*([^\s;]+))?", line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2) or "unknown", "ecosystem": "PyPI"})
    return deps


def parse_pyproject_toml(content: str) -> list[dict]:
    # Minimal TOML parser: project.dependencies
    deps = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = "dependencies" in stripped or "project.dependencies" in stripped
            continue
        if in_deps and "=" in stripped and not stripped.startswith("#"):
            # name = ">=version" or name = "version"
            m = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"', stripped)
            if m:
                deps.append({"name": m.group(1), "version": m.group(2).strip(">=<^~!"), "ecosystem": "PyPI"})
    return deps


def parse_package_json(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ["dependencies", "devDependencies", "peerDependencies"]:
        for name, version in data.get(section, {}).items():
            ver = version.lstrip("^~>=<").strip()
            deps.append({"name": name, "version": ver or "unknown", "ecosystem": "npm"})
    return deps


def parse_go_mod(content: str) -> list[dict]:
    deps = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require") and "(" not in stripped:
            in_require = True
            parts = stripped.split()
            if len(parts) >= 3:
                deps.append({"name": parts[1], "version": parts[2].strip("v"), "ecosystem": "Go"})
            continue
        if stripped == ")":
            in_require = False
            continue
        if in_require:
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append({"name": parts[0], "version": parts[1].strip("v"), "ecosystem": "Go"})
    return deps


def discover_deps(repo_root: str) -> list[dict]:
    deps = []
    for eco, filenames in ECOSYSTEMS.items():
        for fname in filenames:
            path = os.path.join(repo_root, fname)
            if not os.path.isfile(path):
                continue
            content = read_file(path)
            if not content:
                continue
            if eco == "python" and fname in ("requirements.txt", "requirements-dev.txt"):
                deps.extend(parse_python_requirements(content))
            elif eco == "python" and fname == "pyproject.toml":
                deps.extend(parse_pyproject_toml(content))
            elif eco == "javascript" and fname == "package.json":
                deps.extend(parse_package_json(content))
            elif eco == "go" and fname == "go.mod":
                deps.extend(parse_go_mod(content))
    return deps


# ── Vulnerability + license + outdatedness checks ───────────────────────

def query_osv(name: str, version: str, ecosystem: str) -> list[dict]:
    payload = {
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }
    result = api_post(OSV_API, payload)
    if "error" in result:
        return []
    return result.get("vulns", [])


def check_license_pypi(name: str) -> str | None:
    url = f"https://pypi.org/pypi/{name}/json"
    result = api_get(url)
    if "error" in result:
        return None
    info = result.get("info", {})
    lic = info.get("license", "")
    # classifiers
    for classifier in info.get("classifiers", []):
        if classifier.startswith("License ::"):
            lic = classifier.split("::")[-1].strip()
    return lic or None


def check_license_npm(name: str) -> str | None:
    url = f"https://registry.npmjs.org/{name}"
    result = api_get(url)
    if "error" in result:
        return None
    return result.get("license") or None


def check_license_go(name: str) -> str | None:
    # Best effort: proxy.golang.org module metadata (no stable license endpoint)
    # Fallback: Unknown
    return None


def check_outdated_pypi(name: str, current: str) -> str | None:
    url = f"https://pypi.org/pypi/{name}/json"
    result = api_get(url)
    if "error" in result:
        return None
    latest = result.get("info", {}).get("version", current)
    return latest if latest != current else None


def check_outdated_npm(name: str, current: str) -> str | None:
    url = f"https://registry.npmjs.org/{name}"
    result = api_get(url)
    if "error" in result:
        return None
    dist_tags = result.get("dist-tags", {})
    latest = dist_tags.get("latest", current)
    return latest if latest != current else None


def check_outdated_go(name: str, current: str) -> str | None:
    # go list -m -json {name}@latest would require network; skip for speed
    return None


# ── SARIF + Advisory formatting ─────────────────────────────────────────

def to_sarif(findings: list[dict], repo: str) -> dict:
    rules = []
    for f in findings:
        rules.append({
            "id": f"{f['package']}-{f['id']}" if f.get("id") else f"{f['package']}-license",
            "shortDescription": {"text": f["type"].upper()},
            "fullDescription": {"text": f["message"]},
            "properties": {
                "package": f["package"],
                "installedVersion": f.get("installed"),
                "severity": f.get("severity", "medium"),
            },
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "zqm-snyk-replacement", "version": "0.1.0"}},
                "results": [
                    {
                        "ruleId": r["id"],
                        "level": "warning",
                        "message": {"text": r["fullDescription"]["text"]},
                        "properties": r["properties"],
                    }
                    for r in rules
                ],
            }
        ],
    }


def to_github_advisory_comment(findings: list[dict]) -> str:
    if not findings:
        return ":white_check_mark: **zqm-snyk-replacement** — 0 supply-chain issues detected."
    lines = [f"### :warning: zqm-snyk-replacement — {len(findings)} findings\n"]
    for f in findings:
        lines.append(f"- **{f['type'].upper()}** `{f['package']}` @ {f.get('installed', '?')}: {f['message']}")
    lines.append(f"\n_Scanned {datetime.now(timezone.utc).isoformat()}Z_")
    return "\n".join(lines)


def shell_cmd(cmd: list[str], cwd: str) -> dict | None:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return None
        return json.loads(r.stdout)
    except Exception:
        return None


def scan_pip_audit(repo_root: str) -> list[dict]:
    findings = []
    data = shell_cmd(["pip-audit", "--format=json", "--strict"], repo_root)
    if not data:
        return findings
    for item in data:
        name = item.get("name", "")
        version = item.get("version", "")
        vulns = item.get("vulns", [])
        for v in vulns:
            findings.append({
                "type": "vulnerability",
                "package": name,
                "id": v.get("id"),
                "installed": version,
                "severity": v.get("severity", "medium"),
                "message": f"{v.get('id', 'UNKNOWN')}: {v.get('fix_versions', ['no fix'])[0]}",
            })
    return findings


def scan_safety(repo_root: str) -> list[dict]:
    findings = []
    data = shell_cmd(["safety", "check", "--json"], repo_root)
    if not data:
        return findings
    for item in data:
        findings.append({
            "type": "vulnerability",
            "package": item.get("package_name", ""),
            "id": item.get("vulnerability_id"),
            "installed": item.get("analyzed_version", ""),
            "severity": item.get("severity", "medium"),
            "message": f"{item.get('vulnerability_id', 'UNKNOWN')}: {item.get('advisory', '')[:180]}",
        })
    return findings


# ── Main scan ───────────────────────────────────────────────────────────

def scan_repo(repo_root: str, repo_full: str) -> tuple[list[dict], dict]:
    deps = discover_deps(repo_root)
    findings = []
    licenses_checked = {}

    for dep in deps:
        name = dep["name"]
        version = dep["version"]
        ecosystem = dep["ecosystem"]

        # 1. Vulnerabilities
        vulns = query_osv(name, version, ecosystem)
        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            severity = "high"
            desc = vuln.get("details", "")
            affected = vuln.get("affected", [])
            for a in affected:
                for r in a.get("ranges", []):
                    for ev in r.get("events", []):
                        if ev.get("fixed") and version != "unknown":
                            try:
                                if tuple(map(int, ev["fixed"].split("."))) <= tuple(map(int, version.split(".")[:3])):
                                    severity = "critical"
                            except Exception:
                                pass
            aliases = vuln.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
            findings.append({
                "type": "vulnerability",
                "package": name,
                "id": vuln_id,
                "installed": version,
                "severity": severity,
                "message": f"{cve}: {desc[:180]}",
            })

        # 2. License compliance
        license_name = None
        if ecosystem == "PyPI":
            license_name = licenses_checked.get(name) or check_license_pypi(name)
        elif ecosystem == "npm":
            license_name = licenses_checked.get(name) or check_license_npm(name)
        elif ecosystem == "Go":
            license_name = licenses_checked.get(name) or check_license_go(name)

        if license_name:
            licenses_checked[name] = license_name
            # normalize for comparison
            norm_lic = re.sub(r"[\s\-_]+", "", license_name).upper()
            allowed_norm = {re.sub(r"[\s\-_]+", "", l).upper() for l in ALLOWED_LICENSES}
            if norm_lic not in allowed_norm:
                findings.append({
                    "type": "license",
                    "package": name,
                    "id": None,
                    "installed": version,
                    "severity": "medium",
                    "message": f"License `{license_name}` not in allowlist: {sorted(ALLOWED_LICENSES)}",
                })

        # 3. Outdated dependencies
        latest = None
        if ecosystem == "PyPI":
            latest = check_outdated_pypi(name, version)
        elif ecosystem == "npm":
            latest = check_outdated_npm(name, version)
        elif ecosystem == "Go":
            latest = check_outdated_go(name, version)

        if latest:
            findings.append({
                "type": "outdated",
                "package": name,
                "id": None,
                "installed": version,
                "severity": "low",
                "message": f"Update available: {name}@{latest} (installed {version})",
            })

    sarif = to_sarif(findings, repo_full)

    # Secondary sources: pip-audit, safety
    extra = scan_pip_audit(repo_root) + scan_safety(repo_root)
    existing = {(f["type"], f["package"], f.get("id")) for f in findings}
    for f in extra:
        key = (f["type"], f["package"], f.get("id"))
        if key not in existing:
            findings.append(f)
            existing.add(key)

    return findings, sarif


def post_github_advisory(repo_full: str, pr_number: int, comment: str) -> bool:
    token = gh_token()
    if not token or pr_number <= 0:
        return False
    url = f"{GITHUB_API}/repos/{repo_full}/issues/{pr_number}/comments"
    payload = {"body": comment}
    result = api_post(url, payload, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    })
    return "id" in result


def save_artifact(findings: list[dict], sarif: dict, repo_full: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = repo_full.replace("/", "_")
    out_dir = os.path.join(".zqm-security-reports", safe)
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, f"{ts}-findings.json")
    sarif_path = os.path.join(out_dir, f"{ts}-results.sarif")
    with open(json_path, "w") as f:
        json.dump({"repo": repo_full, "scanned_at": ts, "findings": findings}, f, indent=2)
    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"Artifacts: {json_path} | {sarif_path}")
    return sarif_path


# ── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ZQM Snyk Replacement — open-source supply-chain scanner")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/repo")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument("--pr", type=int, default=int(os.environ.get("PR_NUMBER", "0")), help="PR number for comment")
    parser.add_argument("--output", default="sarif", choices=["sarif", "json", "both"], help="Output format")
    parser.add_argument("--no-comment", action="store_true", help="Skip GitHub advisory comment")
    args = parser.parse_args()

    repo_full = args.repo or os.path.basename(os.getcwd())
    repo_root = args.root

    print(f"Scanning {repo_full} @ {repo_root} ...")
    findings, sarif = scan_repo(repo_root, repo_full)
    print(f"Findings: {len(findings)}")

    if args.output in ("sarif", "both"):
        save_artifact(findings, sarif, repo_full)

    if not args.no_comment and args.pr > 0:
        comment = to_github_advisory_comment(findings)
        if post_github_advisory(repo_full, args.pr, comment):
            print(f"Advisory comment posted on PR #{args.pr}")
        else:
            print("Advisory comment skipped (no token or invalid PR)")

    # Print summary
    vulns = sum(1 for f in findings if f["type"] == "vulnerability")
    licenses = sum(1 for f in findings if f["type"] == "license")
    outdated = sum(1 for f in findings if f["type"] == "outdated")
    print(f"  vulnerabilities={vulns} license_issues={licenses} outdated={outdated}")

    if findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
