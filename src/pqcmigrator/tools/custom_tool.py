from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import subprocess
import socket
import ssl
import hashlib
import os
import base64
import re
import json
from datetime import datetime

# cryptography for deep parsing
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ======================================================
# Utility functions
# ======================================================
def format_md5_colon(raw: bytes) -> str:
    md5 = hashlib.md5(raw).hexdigest()
    return ":".join(md5[i:i+2] for i in range(0, len(md5), 2))

def format_sha256(raw: bytes) -> str:
    return base64.b64encode(hashlib.sha256(raw).digest()).decode()


# ======================================================
# Scanner Agent Tools
# ======================================================

# ------------------------- TLS ------------------------
class TLSScannerInput(BaseModel):
    host: str = Field(..., description="Target hostname or IP to scan.")
    port: int = Field(default=443, description="TLS port to scan.")

class TLSScannerTool(BaseTool):
    name: str = "TLSScannerTool"
    description: str = "Scans a host for TLS certificate details including algorithm, key size, fingerprints."
    args_schema: Type[BaseModel] = TLSScannerInput

    def _run(self, host: str, port: int) -> str:
        result = {"host": host, "port": port}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(True)
                    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    result["subject"] = cert.subject.rfc4514_string()
                    result["issuer"] = cert.issuer.rfc4514_string()
                    result["not_valid_before"] = cert.not_valid_before.isoformat()
                    result["not_valid_after"] = cert.not_valid_after.isoformat()

                    pubkey = cert.public_key()
                    if hasattr(pubkey, "key_size"):
                        result["public_key_size"] = pubkey.key_size
                    result["public_key_type"] = pubkey.__class__.__name__

                    result["pem"] = pem_cert
                    result["fingerprint_md5"] = format_md5_colon(der_cert)
                    result["fingerprint_sha256"] = format_sha256(der_cert)

                    result["cipher"] = ssock.cipher()
        except Exception as e:
            result["error"] = f"TLS Scan Failed: {str(e)}"
        return json.dumps(result, indent=2)


# ------------------------- SSH ------------------------
import subprocess, json, base64, hashlib
from typing import Type
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

# --- helpers --------------------------------------------------------

def _md5_colon_from_b64(key_b64: str) -> str:
    """OpenSSH-style MD5 fingerprint as colon-separated hex of the raw key blob."""
    blob = base64.b64decode(key_b64.encode())
    h = hashlib.md5(blob).hexdigest()
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))

def _sha256_from_b64(key_b64: str) -> str:
    """OpenSSH-style SHA256 fingerprint (Base64, no padding)."""
    blob = base64.b64decode(key_b64.encode())
    fp = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{fp}"

def _key_size_from_pubkey_obj(pubkey) -> int | None:
    if isinstance(pubkey, rsa.RSAPublicKey):
        return pubkey.key_size
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return pubkey.curve.key_size  # e.g., 256 for nistp256
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return 256  # Ed25519 keys are 256-bit
    return None

# --- tool -----------------------------------------------------------

class SSHScannerInput(BaseModel):
    host: str = Field(..., description="Target hostname or IP for SSH scan.")
    port: int = Field(default=22, description="SSH port, usually 22.")

class SSHScannerTool(BaseTool):
    name: str = "SSHScannerTool"
    description: str = "Scans a host using ssh-keyscan to retrieve SSH key details (algorithm, size, fingerprints)."
    args_schema: Type[BaseModel] = SSHScannerInput

    def _run(self, host: str, port: int) -> str:
        """
        Uses `ssh-keyscan` to fetch host public keys and derives:
          - algorithm (type)
          - key_size (bits)
          - fingerprint_md5 (OpenSSH colon-hex)
          - fingerprint_sha256 (OpenSSH Base64 form without '=' padding)
        """
        result = {"host": host, "port": port, "keys": []}
        try:
            # -T 5 sets a 5s per-host timeout; adjust if you need longer.
            # We don't restrict -t (type) so we capture whatever the server offers.
            cmd = ["ssh-keyscan", "-T", "5", "-p", str(port), host]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

            lines = [ln for ln in output.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
            if not lines:
                result["error"] = "No SSH keys found or ssh-keyscan returned no usable output."
                return json.dumps(result, indent=2)

            for line in lines:
                # Expected: "<host> <type> <base64> [comment]"
                parts = line.strip().split()
                if len(parts) < 3:
                    # keep raw line for debugging
                    result["keys"].append({"type": None, "error": f"Invalid line format: {line}"})
                    continue

                # host_token can be hashed like |1|..., we don't rely on it.
                _host_token = parts[0]
                key_type = parts[1]
                key_b64 = parts[2]
                comment = " ".join(parts[3:]) if len(parts) > 3 else ""

                try:
                    # cryptography expects the OpenSSH "type base64" form (not the raw decoded blob)
                    pubkey = load_ssh_public_key(f"{key_type} {key_b64}".encode())

                    key_size = _key_size_from_pubkey_obj(pubkey)
                    fp_md5 = _md5_colon_from_b64(key_b64)
                    fp_sha256 = _sha256_from_b64(key_b64)

                    result["keys"].append({
                        "type": key_type,
                        "key_size": key_size,
                        "fingerprint_md5": fp_md5,
                        "fingerprint_sha256": fp_sha256,
                        "comment": comment or None,
                        "source": "ssh-keyscan"
                    })
                except Exception as ex:
                    # Include minimal context to help debug parsing issues.
                    result["keys"].append({
                        "type": key_type,
                        "error": f"Key parse failed: {ex.__class__.__name__}: {str(ex)}",
                        "raw_line": line
                    })

        except subprocess.CalledProcessError as e:
            result["error"] = f"ssh-keyscan failed: {e.output}"
        except FileNotFoundError:
            result["error"] = "ssh-keyscan is not installed or not in PATH."
        except Exception as e:
            result["error"] = f"SSH scan failed: {str(e)}"

        return json.dumps(result, indent=2)



# ------------------------- Codebase -------------------
class CodeScannerInput(BaseModel):
    path: str = Field(..., description="Path to directory or file to scan for secrets and crypto usage.")

class CodeScannerTool(BaseTool):
    name: str = "CodeScannerTool"
    description: str = "Scans code files for secrets, credentials, and weak cryptographic algorithm usage."
    args_schema: Type[BaseModel] = CodeScannerInput

    def _run(self, path: str) -> str:
        result = {"path": path, "findings": []}
        patterns = [
            (r"-----BEGIN (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----", "Private Key"),
            (r"AKIA[0-9A-Z]{16}", "AWS Key ID"),
            (r"(?i)(api[_-]?key|token)[\"'\s:=]{1,4}[A-Za-z0-9\-\._]{8,}", "API Key or Token"),
            (r"(?i)password\s*[:=]\s*['\"].{6,}['\"]", "Hardcoded password"),
            (r"\bssh-rsa\b", "SSH RSA Key"),
            (r"\bMD5\b", "Weak Algorithm (MD5)"),
            (r"\bSHA1\b", "Weak Algorithm (SHA1)"),
            (r"\bDES\b", "Weak Algorithm (DES)"),
            (r"\bRSA\b", "Potential RSA usage"),
            (r"\bDSA\b", "Potential DSA usage"),
        ]

        try:
            if os.path.isfile(path):
                files = [path]
            else:
                files = []
                for root, _, filenames in os.walk(path):
                    for f in filenames:
                        files.append(os.path.join(root, f))

            for file in files:
                try:
                    with open(file, "r", errors="ignore") as f:
                        content = f.read()
                        for pattern, label in patterns:
                            for match in re.finditer(pattern, content):
                                result["findings"].append({
                                    "file": file,
                                    "label": label,
                                    "match": match.group(0)[:200]
                                })
                except Exception:
                    continue
        except Exception as e:
            result["error"] = str(e)
        return json.dumps(result, indent=2)


# ------------------------- YARA ------------------------
class YARAScannerInput(BaseModel):
    paths: str = Field(..., description="Comma-separated list of file paths to simulate YARA scan.")

class YARAScannerTool(BaseTool):
    name: str = "YARAScannerTool"
    description: str = "Simulated YARA scanner to detect key material. Replace with yara-python for production."
    args_schema: Type[BaseModel] = YARAScannerInput

    def _run(self, paths: str) -> str:
        result = {"paths": paths.split(","), "matches": []}
        for p in result["paths"]:
            p = p.strip()
            if not os.path.exists(p):
                result["matches"].append({"file": p, "error": "File not found"})
                continue
            try:
                with open(p, "rb") as f:
                    data = f.read()
                    if b"PRIVATE" in data or b"KEY" in data:
                        result["matches"].append({
                            "file": p,
                            "match": "Potential key material found"
                        })
            except Exception as e:
                result["matches"].append({"file": p, "error": str(e)})
        return json.dumps(result, indent=2)


# ======================================================
# Risk Analyzer Agent Tools
# ======================================================
import json, re
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Type
from pydantic import BaseModel, Field
from enum import Enum

# ---------------- CONFIG (Q-RESISTANCE FOCUS) ----------------
# We focus on *quantum* risk (store-now-decrypt-later and future forgery).
# Classical asymmetric (RSA, DSA, ECDSA/EdDSA incl. Ed25519) ⇒ Broken by Shor (High).
# Symmetric/hash aren’t host keys/certs here, but if present we’d rate:
#   AES-128 ~ Medium (Grover), AES-256 ~ Low; SHA-2/3 preimage ~ Medium/Low.
# TLS hybrid/PQ KEM hints reduce confidentiality risk for KEX to Medium/Low.

PQC_KEM_HINTS = {"ml-kem", "mlkem", "kyber", "x25519mlkem", "hybrid", "mlkem768", "mlkem1024"}
TLS1_3_PREFIXES = {"tls1.3", "tls13", "tlsv1.3"}

# ---------------- MODELS (unchanged inputs) ----------------
class RiskLevel(str, Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Expired = "Expired"

class TLSFinding(BaseModel):
    host: Optional[str] = None
    version: Optional[str] = None                  # e.g., "TLS 1.3"
    public_key_type: Optional[str] = None          # "RSA", "EC", "ECDSA" etc.
    public_key_size: Optional[int] = None          # bits
    signature_algo: Optional[str] = None           # e.g., "ECDSA with SHA-256"
    cipher: Optional[str] = None                   # e.g., "AES_128_GCM"
    kem: Optional[str] = None                      # e.g., "X25519MLKEM768"
    not_valid_after: Optional[str] = None          # ISO 8601

class SSHFinding(BaseModel):
    host: Optional[str] = None
    key_type: Optional[str] = None                 # "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"
    key_size: Optional[int] = None                 # bits (if available)

class CodeFinding(BaseModel):
    file: Optional[str] = None
    label: Optional[str] = None                    # free text

class ScanResults(BaseModel):
    tls: List[TLSFinding] = Field(default_factory=list)
    ssh: List[SSHFinding] = Field(default_factory=list)
    codebase: List[CodeFinding] = Field(default_factory=list)

class RiskAnalyzerInput(BaseModel):
    scan_results: str = Field(..., description="JSON string of scan results from scanner agent.")

# ---------------- HELPERS ----------------
def _norm(s: Optional[str]) -> str:
    return (s or "").strip()

def _low(s: Optional[str]) -> str:
    return _norm(s).lower()

def _tls_version_tag(version: Optional[str]) -> str:
    v = _low(version).replace(" ", "")
    v = v.replace("tlsv", "tls")  # handle "TLSv1.3"
    return v

def _has_pqc_kem(s: Optional[str]) -> bool:
    low = _low(s)
    return any(k in low for k in PQC_KEM_HINTS)

def _algo_from_tls_pubkey(t: TLSFinding) -> str:
    a = _low(t.public_key_type)
    if not a:
        # fall back to signature algo if present
        sig = _low(t.signature_algo)
        if "rsa" in sig:
            return "RSA"
        if "ecdsa" in sig or "ec" in sig:
            return "ECDSA"
        if "ed25519" in sig:
            return "Ed25519"
        return "Unknown"
    if a.startswith("rsa"):
        return "RSA"
    if a in {"ec", "ecdsa", "ecc"}:
        return "ECDSA"
    if "ed25519" in a:
        return "Ed25519"
    return t.public_key_type or "Unknown"

def _algo_from_ssh_keytype(ktype: Optional[str]) -> str:
    k = _low(ktype)
    if k.startswith("ssh-rsa"):
        return "RSA"
    if k.startswith("ecdsa-"):
        return "ECDSA"
    if k.startswith("ssh-ed25519"):
        return "Ed25519"
    if k.startswith("sk-"):  # FIDO/U2F backed, but signatures are still classical
        # e.g., sk-ssh-ed25519@openssh.com
        if "ed25519" in k:
            return "Ed25519 (FIDO)"
        if "ecdsa" in k:
            return "ECDSA (FIDO)"
    return ktype or "Unknown"

# ---------------- QUANTUM-RISK EVALUATION ----------------
def evaluate_tls_quantum(t: TLSFinding) -> Dict[str, Any]:
    """
    PQ-centric evaluation:
      - Authentication (cert signatures & server long-term key): classical → Shor breaks ⇒ High.
      - Confidentiality (KEX): if hybrid/PQ KEM detected (e.g., ML-KEM), reduce to Medium/Low.
      We report a single 'risk' with a reason that explains both aspects briefly.
    """
    host = t.host or "(unknown)"
    alg = _algo_from_tls_pubkey(t)
    size = t.public_key_size
    vtag = _tls_version_tag(t.version)
    kem = t.kem or ""

    pq_kem = _has_pqc_kem(kem)

    # Default: High (classical-only)
    risk = "High"
    reason_bits = []
    if alg in {"RSA", "ECDSA", "Ed25519", "Ed25519 (FIDO)", "ECDSA (FIDO)"}:
        reason_bits.append(f"{alg} signatures are classical—broken by Shor")

    # KEX consideration (store-now-decrypt-later):
    if vtag in TLS1_3_PREFIXES:
        if pq_kem:
            # Hybrid/PQ KEM mitigates confidentiality (but auth still classical)
            risk = "Medium"
            reason_bits.append(f"Hybrid/PQ KEM detected ({t.kem}) for key exchange")
        else:
            reason_bits.append("Classical-only key exchange (vulnerable to store-now-decrypt-later)")
    else:
        # TLS < 1.3 is classical KEX; keep High
        reason_bits.append("Non-PQ key exchange")

    # Add size note (informational only; does not change quantum risk)
    if size:
        reason_bits.append(f"cert key size: {size} bits")

    return {
        "asset": f"TLS certificate for {host}",
        "algorithm": alg,
        "key_size": size,
        "risk": risk,
        "reason": "; ".join(reason_bits) or "Classical cryptography; not quantum-resistant"
    }

def evaluate_ssh_quantum(s: SSHFinding) -> Dict[str, Any]:
    """
    SSH host keys today are classical (RSA/ECDSA/Ed25519). Under Shor, all are breakable.
    There is no standardized PQC for SSH host authentication yet → High.
    """
    host = s.host or "(unknown)"
    alg = _algo_from_ssh_keytype(s.key_type)
    size = s.key_size

    reason_bits = []
    if alg.startswith("RSA"):
        reason_bits.append("RSA signatures are classical—broken by Shor")
    elif alg.startswith("ECDSA"):
        reason_bits.append("ECDSA (elliptic-curve discrete log) broken by Shor")
    elif alg.startswith("Ed25519"):
        reason_bits.append("Ed25519 (elliptic-curve discrete log) broken by Shor")
    else:
        reason_bits.append("Unknown/legacy SSH key type (assume classical)")

    if size:
        reason_bits.append(f"host key size: {size} bits")

    return {
        "asset": f"SSH key on host {host}",
        "algorithm": alg,
        "key_size": size,
        "risk": "High",  # until standardized PQ host keys exist/deployed
        "reason": "; ".join(reason_bits)
    }

def evaluate_code_quantum(c: CodeFinding) -> Dict[str, Any]:
    """
    Very coarse PQ lens for code findings (if provided):
      - If label hints at ML-KEM/Dilithium/SLH-DSA → Low
      - If label hints at RSA/ECDSA/Ed25519 → High
      - Else → Medium (unknown posture)
    """
    label = _low(c.label)
    alg = "Unknown"
    risk = "Medium"
    reason = "Posture unknown"

    if any(k in label for k in ("ml-kem", "mlkem", "kyber", "ml-dsa", "dilithium", "slh-dsa", "sphincs")):
        alg = "PQC"
        risk = "Low"
        reason = "Post-quantum primitive referenced"
    elif any(k in label for k in ("rsa", "ecdsa", "ed25519", "x25519", "ecdh", "ecdsA")):
        alg = "Classical"
        risk = "High"
        reason = "Classical primitive referenced (broken by Shor)"
    return {
        "asset": f"Code {c.file or '(unknown)'}",
        "algorithm": alg,
        "key_size": None,
        "risk": risk,
        "reason": reason if c.label is None else f"{reason}: {c.label}"
    }

# ---------------- TOOL (outputs a JSON LIST) ----------------
class RiskAnalyzerTool(BaseTool):
    name: str = "RiskAnalyzerTool"
    description: str = "Evaluates cryptographic assets with a quantum-resistance lens and assigns risk levels."
    args_schema: Type[BaseModel] = RiskAnalyzerInput

    def _run(self, scan_results: str) -> str:
        # Parse input JSON safely into our model
        try:
            payload = json.loads(scan_results)
            data = ScanResults(**payload)
        except Exception as e:
            # Output still as a list (with a single error object) to match required format
            return json.dumps([{
                "asset": "parse_error",
                "algorithm": "Unknown",
                "key_size": None,
                "risk": "High",
                "reason": f"Invalid input JSON: {str(e)}"
            }], indent=2)

        out: List[Dict[str, Any]] = []

        # TLS findings → PQ view (auth classical, KEX maybe hybrid)
        for t in data.tls:
            out.append(evaluate_tls_quantum(t))

        # SSH host keys → PQ view (all classical today)
        for s in data.ssh:
            out.append(evaluate_ssh_quantum(s))

        # Code findings (optional) → coarse PQ view
        for c in data.codebase:
            out.append(evaluate_code_quantum(c))

        # Return EXACTLY a JSON list as requested
        return json.dumps(out, indent=2)




# # ======================================================
# # Planner Agent Tools
# # ======================================================
# class PlannerInput(BaseModel):
#     risks: str = Field(..., description="JSON string of risk evaluation results.")

# class PlannerTool(BaseTool):
#     name: str = "PlannerTool"
#     description: str = "Creates a PQC migration plan based on risks, mapping classical algorithms to NIST PQC replacements."
#     args_schema: Type[BaseModel] = PlannerInput

#     def _run(self, risks: str) -> str:
#         try:
#             risk_data = json.loads(risks)
#         except Exception as e:
#             return json.dumps({"error": f"Invalid input JSON: {str(e)}"}, indent=2)

#         pqc_map = {
#             "RSA": "CRYSTALS-Kyber",
#             "ECDSA": "Dilithium",
#             "DSA": "Dilithium",
#             "SHA1": "SHA3-256",
#             "MD5": "SHA3-256",
#         }

#         plan = []
#         priority = 1
#         for asset in risk_data:
#             algo = asset.get("issue", "RSA")
#             replacement = pqc_map.get(algo, "SPHINCS+")
#             plan.append({
#                 "asset": asset.get("asset"),
#                 "risk": asset.get("risk"),
#                 "recommended_replacement": replacement,
#                 "priority": priority
#             })
#             priority += 1

#         return json.dumps({"plan": plan}, indent=2)


# # ======================================================
# # Migrator Agent Tools
# # ======================================================
# class MigratorInput(BaseModel):
#     plan: str = Field(..., description="JSON string migration plan from planner.")

# class MigratorTool(BaseTool):
#     name: str = "MigratorTool"
#     description: str = "Executes the migration plan (simulated) by generating PQC keys/certs and updating configs."
#     args_schema: Type[BaseModel] = MigratorInput

#     def _run(self, plan: str) -> str:
#         try:
#             plan_data = json.loads(plan)
#         except Exception as e:
#             return json.dumps({"error": f"Invalid input JSON: {str(e)}"}, indent=2)

#         executed, failed = [], []

#         for item in plan_data.get("plan", []):
#             asset = item.get("asset")
#             replacement = item.get("recommended_replacement")
#             risk = item.get("risk")

#             if risk == "High":
#                 executed.append({
#                     "asset": asset,
#                     "action": f"Migrated to {replacement}",
#                     "status": "Success"
#                 })
#             else:
#                 failed.append({
#                     "asset": asset,
#                     "reason": "Migration not required or pending manual approval"
#                 })

#         return json.dumps({"executed": executed, "failed": failed}, indent=2)


# # ======================================================
# # Rollback Agent Tools
# # ======================================================
# class RollbackInput(BaseModel):
#     migration_report: str = Field(..., description="JSON migration execution report from migrator.")

# class RollbackTool(BaseTool):
#     name: str = "RollbackTool"
#     description: str = "Restores system state if migration failed using backups."
#     args_schema: Type[BaseModel] = RollbackInput

#     def _run(self, migration_report: str) -> str:
#         try:
#             report = json.loads(migration_report)
#         except Exception as e:
#             return json.dumps({"error": f"Invalid input JSON: {str(e)}"}, indent=2)

#         restored = []
#         if report.get("failed"):
#             for f in report["failed"]:
#                 restored.append(f["asset"])

#         rollback_info = {
#             "rollback_triggered": bool(restored),
#             "assets_restored": restored,
#             "status": "System restored to safe state" if restored else "No rollback needed"
#         }
#         return json.dumps(rollback_info, indent=2)
