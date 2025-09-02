#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, json, base64, hashlib
from typing import Any, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel, Field

# CrewAI / Tool base (with fallback to LangChain BaseTool)
try:
    from crewai.tools import BaseTool  # CrewAI >= 0.36
except Exception:  # pragma: no cover
    from langchain.tools import BaseTool  # type: ignore

# =========================
# Pydantic input schema
# =========================

class CodeScannerInput(BaseModel):
    path: str = Field(..., description="Path to directory or file to scan for secrets and crypto usage.")


# =========================
# Main Tool
# =========================

class CodeScannerTool(BaseTool):
    """
    CrewAI-compatible source code scanner for secrets & crypto usage.

    - Scans selected text-like files (by extension and heuristic) with size limits.
    - Detects:
        * Private keys, certs, PGP blocks
        * API keys, tokens, AWS access keys, JWTs
        * Hardcoded passwords
        * Weak hashes (MD5, SHA1) & legacy ciphers (DES/3DES/RC4)
        * Common OpenSSL/PKCS indicators
        * SSH public key formats
        * General RSA/EC/Ed25519 indicators
    - Returns per-finding context (few lines) and a summary with counts.

    Safety/Perf:
    - Skips binary files (NUL byte), huge files, and common vendor/cache dirs.
    - Heuristics aim to reduce noise but keep useful signals.
    """
    name: str = "CodeScannerTool"
    description: str = "Scans code files for secrets, credentials, and weak cryptographic algorithm usage."
    args_schema: Type[BaseModel] = CodeScannerInput

    # Configurable knobs
    DEFAULT_EXTS: Tuple[str, ...] = (
        ".py",".js",".ts",".tsx",".jsx",".java",".c",".cpp",".go",".rs",".sh",".rb",".php",
        ".json",".env",".yml",".yaml",".conf",".ini",".toml",".gradle",".cfg",
        ".pem",".key",".crt",".cer",".p12",".pfx",".der",".csr",
        ".txt",".md",".xml",".properties"
    )
    SKIP_DIRS: Tuple[str, ...] = (
        ".git",".hg",".svn",".idea",".vscode","node_modules","dist","build",
        "__pycache__",".mypy_cache",".pytest_cache",".ruff_cache",".venv","venv",".cache","target",".gradle"
    )
    MAX_FILE_BYTES: int = 2_000_000  # 2 MB per file cap
    CONTEXT_LINES: int = 3

    # Detection rules (compiled at init)
    RULES: List[Tuple[str, str, str]] = [
        # Private material / certs
        (r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", "HIGH", "Private key block"),
        (r"BEGIN PGP PRIVATE KEY BLOCK",                                  "HIGH", "PGP private key block"),
        (r"-----BEGIN CERTIFICATE-----",                                  "INFO", "Certificate PEM block"),
        (r"ssh-(rsa|ed25519)|ecdsa-sha2-nistp\d+",                        "INFO", "SSH public key format"),

        # Credentials / tokens
        (r"\bAKIA[0-9A-Z]{16}\b",                                         "HIGH", "AWS Access Key ID"),
        (r"\bASIA[0-9A-Z]{16}\b",                                         "HIGH", "AWS Temporary Access Key ID"),
        (r"(?i)(api[_-]?key|apikey|token|auth[_-]?token|client[_-]?secret|secret)[\"'\s:=]{1,6}[A-Za-z0-9\-._]{12,}",
                                                                          "HIGH", "API key / token / secret"),
        (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                                                                          "HIGH", "JWT token-like string"),
        (r"(?i)\bpassword\s*[:=]\s*['\"]?.{6,}['\"]?",                    "MEDIUM", "Hardcoded password (heuristic)"),

        # Weak hashes / ciphers / protocols
        (r"\bMD5\b",                                                      "HIGH", "Weak hash algorithm (MD5)"),
        (r"\bSHA-?1\b",                                                   "HIGH", "Weak hash algorithm (SHA-1)"),
        (r"\b(?:DES|3DES|RC4)\b",                                         "HIGH", "Weak/legacy cipher mention"),
        (r"\bcbc(?:-|\s|_)?mode\b",                                       "MEDIUM", "CBC mode mention (check usage)"),

        # Crypto use hints / OpenSSL
        (r"\bRSA\s*\(\s*\d+\s*\)",                                        "INFO", "RSA keysize literal"),
        (r"\b(ECDSA|ECDH|Ed25519|Ed448|secp\d+(?:r1)?)\b",                "INFO", "EC/EdDSA indicators"),
        (r"\b(AES-(?:128|192|256)|AES\.new|Crypto\.Cipher|from Crypto\.Cipher)\b",
                                                                          "INFO", "AES/cipher usage"),
        (r"\b(EVP_|EVP_PKEY|PKCS(?:#)?1|PKCS(?:#)?8|X509|X\.509)\b",      "INFO", "OpenSSL/PKCS indicators"),
        (r"\bopenssl\s+(genp?key|genrsa|req|ecparam|dgst|pkcs8|pkcs12)\b","INFO", "OpenSSL CLI usage"),
    ]

    # Optional allowlist to suppress known safe test strings (add your own)
    ALLOWLIST: List[re.Pattern] = [
        re.compile(r"example[_-]?key", re.IGNORECASE),
        re.compile(r"dummy|test(?:ing)?[_-]?token", re.IGNORECASE),
    ]

    # ----------------------------------
    # CrewAI entrypoint
    # ----------------------------------
    def _run(self, path: str) -> str:
        result = self.scan(path)
        return json.dumps(result, indent=2)

    # ----------------------------------
    # Core scanning implementation
    # ----------------------------------
    def scan(self, path: str) -> Dict[str, Any]:
        rules = [(re.compile(p, re.IGNORECASE | re.MULTILINE), sev, desc) for p, sev, desc in self.RULES]
        findings: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        # Build file list
        files = self._gather_files(path)

        files_scanned = 0
        matched_files = set()

        for fp in files:
            try:
                if not self._should_scan_file(fp):
                    continue

                content = self._read_text_safe(fp, max_bytes=self.MAX_FILE_BYTES)
                if content is None:
                    continue

                files_scanned += 1
                lines = content.splitlines()

                for cre, sev, desc in rules:
                    for m in cre.finditer(content):
                        if self._allowlisted(m.group(0)):
                            continue
                        lineno = content.count("\n", 0, m.start()) + 1
                        ctx = self._context_snippet(lines, lineno, self.CONTEXT_LINES)

                        finding = {
                            "file": fp,
                            "line": lineno,
                            "severity": sev,
                            "label": desc,
                            "match": m.group(0)[:500],
                            "context": ctx[:2000],
                            "rule": cre.pattern,
                        }
                        findings.append(finding)
                        matched_files.add(fp)

                        # For high-signal rules (private keys / aws keys / jwt / md5/sha1),
                        # we don't need every overlap; continue scanning next rule.
                        if sev in ("HIGH",):
                            break

            except Exception as e:
                errors.append({"file": fp, "error": str(e)})

        summary = self._summarize(findings, files_scanned, len(matched_files))

        return {
            "path": os.path.abspath(path),
            "summary": summary,
            "findings": findings,
            "errors": errors or None,
        }

    # ----------------------------------
    # Helpers
    # ----------------------------------
    def _gather_files(self, path: str) -> List[str]:
        if os.path.isfile(path):
            return [path]
        files: List[str] = []
        for root, dirs, filenames in os.walk(path):
            # Prune skipped directories in-place for speed
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for f in filenames:
                files.append(os.path.join(root, f))
        return files

    def _should_scan_file(self, fp: str) -> bool:
        try:
            st = os.stat(fp)
            if st.st_size == 0 or st.st_size > self.MAX_FILE_BYTES:
                return False
        except Exception:
            return False

        ext = os.path.splitext(fp)[1].lower()
        if ext in self.DEFAULT_EXTS:
            return True

        # Heuristic: peek small files for PEM/private-key text even if extension uncommon
        content = self._read_text_safe(fp, max_bytes=64_000)
        if content and re.search(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", content, re.IGNORECASE):
            return True

        # If the file looks like text but unknown extension, we may still scan lightly
        return bool(content)

    def _read_text_safe(self, path: str, max_bytes: int = 200_000) -> Optional[str]:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(max_bytes)
            if b"\x00" in raw:
                return None
            try:
                return raw.decode("utf-8", errors="ignore")
            except Exception:
                return raw.decode("latin-1", errors="ignore")
        except Exception:
            return None

    def _context_snippet(self, lines: List[str], lineno: int, ctx: int = 3) -> str:
        start = max(0, lineno - ctx - 1)
        end = min(len(lines), lineno + ctx)
        return "\n".join(lines[start:end])

    def _allowlisted(self, text: str) -> bool:
        try:
            for cre in self.ALLOWLIST:
                if cre.search(text):
                    return True
        except Exception:
            pass
        return False

    def _summarize(self, findings: List[Dict[str, Any]], files_scanned: int, matched_files: int) -> Dict[str, Any]:
        sev_counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
        type_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
            type_counts[f["label"]] = type_counts.get(f["label"], 0) + 1

        return {
            "files_scanned": files_scanned,
            "matched_files": matched_files,
            "total_findings": len(findings),
            "by_severity": sev_counts,
            "by_label": type_counts,
            "notes": [
                "Findings are regex-based heuristics. Manually review before acting.",
                "Consider adding project-specific allowlist patterns to reduce false positives.",
            ],
        }
