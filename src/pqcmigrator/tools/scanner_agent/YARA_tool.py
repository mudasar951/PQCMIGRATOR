#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, json, concurrent.futures
from typing import Any, Dict, List, Optional, Tuple, Type
from datetime import datetime, timezone

# Optional YARA import (graceful fallback if unavailable)
try:
    import yara  # type: ignore
except Exception:
    yara = None  # type: ignore

# CrewAI / Tool base (fallback to LangChain if needed)
try:
    from crewai.tools import BaseTool  # CrewAI >= 0.36
except Exception:  # pragma: no cover
    from langchain.tools import BaseTool  # type: ignore

from pydantic import BaseModel, Field


# =========================
# Small helpers
# =========================

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =========================
# Pydantic input schema
# =========================

class YARAScannerInput(BaseModel):
    paths: str = Field(..., description="Comma-separated list of file/dir paths to scan.")
    # Keep CrewAI interface stable; optional toggles with sensible defaults:
    recursive: bool = Field(default=True, description="Recurse into directories.")
    max_file_size_mb: int = Field(default=10, description="Skip files larger than this many MB.")
    threads: int = Field(default=6, description="Worker threads for parallel scanning.")


# =========================
# Main Tool (CrewAI entry)
# =========================

class YARAScannerTool(BaseTool):
    """
    CrewAI-compatible YARA scanner with graceful fallback when yara-python is not installed.

    - Input: comma-separated paths (files or directories).
    - If yara is available:
        * Compiles default rules (private keys, certs, tokens, AWS IDs, JWTs) or custom (advanced API below).
        * Scans files up to a size limit, in parallel.
        * Returns rule matches per file.
    - If yara is NOT available:
        * Runs a lightweight byte-pattern simulation for key materials as a fallback.

    Stable interface: _run(paths: str, recursive=True, max_file_size_mb=10, threads=6) -> JSON string.
    """
    name: str = "YARAScannerTool"
    description: str = "YARA-like scanner to detect key material and secrets. Uses yara-python if available; falls back to byte-patterns otherwise."
    args_schema: Type[BaseModel] = YARAScannerInput

    # Defaults for the tool
    DEFAULT_RULES = r"""
rule PossiblePrivateKey
{
    strings:
        $pem1 = "-----BEGIN PRIVATE KEY-----" nocase
        $pem2 = "-----BEGIN RSA PRIVATE KEY-----" nocase
        $pem3 = "-----BEGIN EC PRIVATE KEY-----" nocase
        $pem4 = "-----BEGIN OPENSSH PRIVATE KEY-----" nocase
    condition:
        any of them
}

rule CertificatePEM
{
    strings:
        $c1 = "-----BEGIN CERTIFICATE-----" nocase
    condition:
        any of them
}

rule AWSAccessKeyID
{
    strings:
        $a1 = /AKIA[0-9A-Z]{16}/
        $a2 = /ASIA[0-9A-Z]{16}/
    condition:
        any of them
}

rule JWTTokenLike
{
    strings:
        $j1 = /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/
    condition:
        any of them
}
"""

    # CrewAI entrypoint
    def _run(self, paths: str, recursive: bool = True, max_file_size_mb: int = 10, threads: int = 6) -> str:
        # Split & clean paths
        path_list = [p.strip() for p in paths.split(",") if p.strip()]
        scanner = YARAScanner(
            rules_text=self.DEFAULT_RULES,
            max_file_size=max(1, int(max_file_size_mb)) * 1024 * 1024
        )

        result = scanner.scan_paths(path_list, recursive=bool(recursive), threads=max(1, int(threads)))
        # Enrich top-level summary a bit
        result["ts"] = now_utc_iso()
        result["yara_available"] = bool(yara is not None and scanner._rules is not None)
        result["paths"] = path_list
        return json.dumps(result, indent=2)


# =========================
# Library class (programmatic use)
# =========================

class YARAScanner:
    """
    Programmatic YARA scanner with optional fallback when yara-python is unavailable.

    Use:
        scanner = YARAScanner()  # compiles DEFAULT_RULES if yara present
        out = scanner.scan_paths(["/etc/ssh", "/tmp/key.pem"], recursive=True, threads=6)

    Output shape:
        {
          "scanned": <int>,           # number of files considered
          "findings": [               # per-file findings (matches, errors, or skipped)
            {"file": "...", "matches": ["RuleName", ...]},
            {"file": "...", "error": "..."},
            {"file": "...", "skipped": "too_large"}
          ]
        }
    """
    # More complete default rules (same as tool’s, but accessible here)
    DEFAULT_RULES = YARAScannerTool.DEFAULT_RULES

    def __init__(self, rules_text: Optional[str] = None, max_file_size: int = 10 * 1024 * 1024):
        self.max_file_size = int(max_file_size)
        self.rules_text = rules_text or self.DEFAULT_RULES
        self._rules = None
        if yara is not None:
            try:
                self._rules = yara.compile(source=self.rules_text)
            except Exception:
                self._rules = None  # compile failure → fallback mode

    def scan_paths(self, paths: List[str], recursive: bool = True, threads: int = 6) -> Dict[str, Any]:
        # Gather candidate files
        targets: List[str] = []
        for p in paths:
            if os.path.isdir(p):
                if recursive:
                    for root, _, files in os.walk(p):
                        for f in files:
                            targets.append(os.path.join(root, f))
                else:
                    for f in os.listdir(p):
                        fp = os.path.join(p, f)
                        if os.path.isfile(fp):
                            targets.append(fp)
            elif os.path.isfile(p):
                targets.append(p)
            else:
                # non-existent paths still get reported as not found below
                targets.append(p)

        results: List[Dict[str, Any]] = []

        # Choose backend
        if yara is None or self._rules is None:
            # Fallback: lightweight byte-pattern checks (no YARA)
            def _fallback_scan(fp: str) -> Optional[Dict[str, Any]]:
                if not os.path.exists(fp):
                    return {"file": fp, "error": "File not found"}
                try:
                    st = os.stat(fp)
                    if st.st_size > self.max_file_size:
                        return {"file": fp, "skipped": "too_large"}
                    with open(fp, "rb") as fh:
                        data = fh.read()
                    matches = []
                    # Simple signatures
                    for marker, rulename in [
                        (b"-----BEGIN PRIVATE KEY-----", "PossiblePrivateKey"),
                        (b"-----BEGIN RSA PRIVATE KEY-----", "PossiblePrivateKey"),
                        (b"-----BEGIN EC PRIVATE KEY-----", "PossiblePrivateKey"),
                        (b"-----BEGIN OPENSSH PRIVATE KEY-----", "PossiblePrivateKey"),
                        (b"-----BEGIN CERTIFICATE-----", "CertificatePEM"),
                    ]:
                        if marker in data:
                            matches.append(rulename)
                    # AWS IDs & JWT-like (text search)
                    try:
                        text = data.decode("utf-8", errors="ignore")
                        if re.search(r"\bAKIA[0-9A-Z]{16}\b", text):
                            matches.append("AWSAccessKeyID")
                        if re.search(r"\bASIA[0-9A-Z]{16}\b", text):
                            matches.append("AWSAccessKeyID")
                        if re.search(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", text):
                            matches.append("JWTTokenLike")
                    except Exception:
                        pass

                    if matches:
                        return {"file": fp, "matches": sorted(set(matches))}
                    return None
                except Exception as e:
                    return {"file": fp, "error": str(e)}

            with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
                futs = {ex.submit(_fallback_scan, f): f for f in targets}
                for fut in concurrent.futures.as_completed(futs):
                    r = fut.result()
                    if r:
                        results.append(r)

            return {"scanned": len(targets), "findings": results, "engine": "fallback"}

        # YARA-backed scanning
        def _yara_scan(fp: str) -> Optional[Dict[str, Any]]:
            if not os.path.exists(fp):
                return {"file": fp, "error": "File not found"}
            try:
                st = os.stat(fp)
                if st.st_size > self.max_file_size:
                    return {"file": fp, "skipped": "too_large"}
                with open(fp, "rb") as fh:
                    data = fh.read()
                ms = self._rules.match(data=data)  # type: ignore
                if ms:
                    return {"file": fp, "matches": [m.rule for m in ms]}
                return None
            except Exception as e:
                return {"file": fp, "error": str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            futs = {ex.submit(_yara_scan, f): f for f in targets}
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                if r:
                    results.append(r)

        return {"scanned": len(targets), "findings": results, "engine": "yara"}
