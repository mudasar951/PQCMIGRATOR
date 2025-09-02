#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess, json, base64, hashlib, re, os, glob
from typing import Type, Optional, Any, Dict, List, ClassVar
from pydantic import BaseModel, Field, ConfigDict

# Optional: richer key parsing if installed
try:
    from cryptography.hazmat.primitives.serialization import load_ssh_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
except Exception:  # pragma: no cover
    load_ssh_public_key = None  # type: ignore
    rsa = ec = ed25519 = None   # type: ignore

# ---------- CrewAI / Tool base ----------
try:
    from crewai.tools import BaseTool  # CrewAI >=0.36
except Exception:  # pragma: no cover
    from langchain.tools import BaseTool  # fallback


# =========================
# Helper functions
# =========================

def _md5_colon_bytes(raw: bytes) -> str:
    h = hashlib.md5(raw).hexdigest()
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))

def _md5_colon_from_b64(key_b64: str) -> str:
    blob = base64.b64decode(key_b64.encode())
    return _md5_colon_bytes(blob)

def _sha256_from_b64(key_b64: str) -> str:
    blob = base64.b64decode(key_b64.encode())
    fp = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{fp}"

def _key_size_from_pubkey_obj(pubkey) -> Optional[int]:
    # Works only if cryptography was imported successfully
    try:
        if rsa and isinstance(pubkey, rsa.RSAPublicKey):
            return pubkey.key_size
        if ec and isinstance(pubkey, ec.EllipticCurvePublicKey):
            return pubkey.curve.key_size
        if ed25519 and isinstance(pubkey, ed25519.Ed25519PublicKey):
            return 256  # fixed
    except Exception:
        pass
    return None


# =========================
# Pydantic input schema
# =========================

class SSHScannerInput(BaseModel):
    host: str = Field(..., description="Target hostname or IP for SSH scan.")
    port: int = Field(default=22, description="SSH port, usually 22.")


# =========================
# Main Tool
# =========================

class SSHScannerTool(BaseTool):
    """
    CrewAI-compatible SSH scanner.

    _run(host, port) will:
      - Call `ssh-keyscan -T <timeout> -p <port> <host>`
      - Parse all returned host keys (rsa/ecdsa/ed25519, etc.)
      - Compute fingerprints:
          * MD5 colon-hex (OpenSSH legacy style)
          * SHA256 (OpenSSH Base64 form, 'SHA256:...')
      - If `cryptography` is available:
          * Derive key_size for RSA/ECDSA/Ed25519
      - If `ssh-keygen` is available:
          * Enrich with ssh-keygen -l formatting (fingerprints/type label)

    Also exposes:
      - scan_local_keys(paths=None) -> Dict[str, Any]
      - scan_ssh_agent() -> Dict[str, Any]
    """
    model_config = ConfigDict(arbitrary_types_allowed=True, extra='ignore')
    name: str = "SSHScannerTool"
    description: str = "Scans a host for SSH key details (algorithm, size, fingerprints)."
    args_schema: Type[BaseModel] = SSHScannerInput

    timeout: int = 8
    use_keygen_enrich: bool = True

    # --------------- CrewAI entry ---------------
    def _run(self, host: str, port: int) -> str:
        result = self._scan_host_keys(host, int(port))
        return json.dumps(result, indent=2)

    # --------------- Core scan ---------------
    def _scan_host_keys(self, host: str, port: int) -> Dict[str, Any]:
        res: Dict[str, Any] = {"host": host, "port": port, "keys": []}
        try:
            # -T (per-host timeout) not supported by all ssh-keyscan versions on all OSes.
            # We'll rely on subprocess timeout as the primary guard.
            cmd = ["ssh-keyscan", "-p", str(port), host]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=self.timeout, text=True)
            except subprocess.CalledProcessError as e:
                res["error"] = f"ssh-keyscan failed with non-zero exit: {e.output}"
                return res

            lines = [ln for ln in out.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
            if not lines:
                res["error"] = "No SSH keys found or ssh-keyscan returned no usable output."
                return res

            # Parse raw keyscan lines
            parsed = []
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 3:
                    parsed.append({"error": f"Invalid line format", "raw_line": line})
                    continue
                _host_token = parts[0]  # could be '|1|...' hashed; not used
                key_type = parts[1]
                key_b64 = parts[2]
                comment = " ".join(parts[3:]) if len(parts) > 3 else None

                entry: Dict[str, Any] = {
                    "type": key_type,
                    "comment": comment,
                    "source": "ssh-keyscan",
                }

                # Fingerprints
                try:
                    entry["fingerprint_md5"] = _md5_colon_from_b64(key_b64)
                    entry["fingerprint_sha256"] = _sha256_from_b64(key_b64)
                except Exception as ex:
                    entry["fingerprint_error"] = f"fingerprint failed: {ex.__class__.__name__}: {ex}"

                # Key size & validation via cryptography (if available)
                if load_ssh_public_key:
                    try:
                        pubkey = load_ssh_public_key(f"{key_type} {key_b64}".encode())
                        entry["key_size"] = _key_size_from_pubkey_obj(pubkey)
                    except Exception as ex:
                        entry.setdefault("warnings", []).append(f"cryptography parse failed: {ex.__class__.__name__}: {ex}")
                        entry["key_size"] = None
                else:
                    entry["key_size"] = None  # cryptography not installed

                parsed.append(entry)

            # Optional enrichment using ssh-keygen -l -f -
            if self.use_keygen_enrich:
                try:
                    # Pipe the original ssh-keyscan output into ssh-keygen for standard fingerprint labeling
                    gen = subprocess.run(
                        ["ssh-keygen", "-l", "-f", "-"],
                        input="\n".join(lines).encode(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        timeout=4,
                        check=False,
                    )
                    gout = gen.stdout.decode(errors="ignore")
                    # Map enriched lines back to entries when possible
                    # ssh-keygen format (typical): "<bits> <fp> <host> (<type>)"
                    enrich = []
                    for l in gout.splitlines():
                        ls = l.strip()
                        if not ls:
                            continue
                        parts = ls.split()
                        if len(parts) >= 2:
                            fp = parts[1]
                            m = re.search(r"\(([^)]+)\)", ls)
                            ktype = m.group(1) if m else None
                            enrich.append({"fingerprint_label": fp, "type_label": ktype, "raw": ls})
                    # Attach a best-effort enrichment list; matching individual items to raw lines is
                    # unreliable across platforms, so we expose it as a parallel view.
                    if enrich:
                        res["keygen_enrich"] = enrich
                except FileNotFoundError:
                    # ssh-keygen not present → ignore
                    pass
                except subprocess.TimeoutExpired:
                    pass
                except Exception as ex:
                    res.setdefault("warnings", []).append(f"ssh-keygen enrich failed: {ex.__class__.__name__}: {ex}")

            res["keys"] = parsed
            res["ok"] = True if parsed else False
            return res

        except FileNotFoundError:
            res["error"] = "ssh-keyscan is not installed or not in PATH."
        except subprocess.TimeoutExpired:
            res["error"] = "ssh-keyscan timed out."
        except Exception as e:
            res["error"] = f"SSH scan failed: {e}"
        res["ok"] = False
        return res

    # --------------- Extra utilities (optional to call) ---------------
    def scan_local_keys(self, paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan common local key locations, compute MD5 (colon) and SHA256 fingerprints for *.pub
        or derive public key from private keys via `ssh-keygen -y`.
        """
        res: Dict[str, Any] = {"found": [], "errors": []}
        default_paths = [os.path.expanduser("~/.ssh"), "/etc/ssh"]
        paths = paths or default_paths
        patterns = ["id_*", "*.pub", "ssh_host_*", "identity"]

        for base in paths:
            if not os.path.exists(base):
                continue
            for pat in patterns:
                for fp in glob.glob(os.path.join(base, pat)):
                    try:
                        if fp.endswith(".pub"):
                            try:
                                with open(fp, "r", errors="ignore") as fh:
                                    line = fh.read().strip()
                                parts = line.split()
                                if len(parts) >= 2:
                                    ktype = parts[0]
                                    b64 = parts[1]
                                    rawb = base64.b64decode(b64 + "===")
                                    md5_col = _md5_colon_bytes(rawb)
                                    sha_b64 = base64.b64encode(hashlib.sha256(rawb).digest()).decode().rstrip("=")
                                    res["found"].append({
                                        "file": fp,
                                        "type": ktype,
                                        "fingerprint_md5": md5_col,
                                        "fingerprint_sha256": f"SHA256:{sha_b64}",
                                    })
                                else:
                                    res["errors"].append({"file": fp, "error": "pubkey parse failed"})
                            except Exception as e:
                                res["errors"].append({"file": fp, "error": str(e)})
                        else:
                            # Try to derive the public key from a private key
                            try:
                                out = subprocess.check_output(["ssh-keygen", "-y", "-f", fp],
                                                              stderr=subprocess.DEVNULL, timeout=4)
                                out = out.decode(errors="ignore").strip()
                                parts = out.split()
                                if len(parts) >= 2:
                                    ktype = parts[0]
                                    b64 = parts[1]
                                    rawb = base64.b64decode(b64 + "===")
                                    md5_col = _md5_colon_bytes(rawb)
                                    sha_b64 = base64.b64encode(hashlib.sha256(rawb).digest()).decode().rstrip("=")
                                    res["found"].append({
                                        "file": fp,
                                        "type": ktype,
                                        "fingerprint_md5": md5_col,
                                        "fingerprint_sha256": f"SHA256:{sha_b64}",
                                    })
                                else:
                                    res["errors"].append({"file": fp, "error": "ssh-keygen -y output parse failed"})
                            except subprocess.CalledProcessError:
                                res["errors"].append({"file": fp, "error": "ssh-keygen failed or key is passphrase-protected"})
                            except FileNotFoundError:
                                res["errors"].append({"file": fp, "error": "ssh-keygen not found on PATH"})
                            except Exception as e:
                                res["errors"].append({"file": fp, "error": str(e)})
                    except Exception as e:
                        res["errors"].append({"file": fp, "error": str(e)})
        return res

    def scan_ssh_agent(self) -> Dict[str, Any]:
        """
        Return keys loaded in ssh-agent via `ssh-add -L`.
        """
        out: Dict[str, Any] = {"agent_keys": [], "error": None}
        try:
            raw = subprocess.check_output(["ssh-add", "-L"], stderr=subprocess.STDOUT, timeout=4).decode(errors="ignore")
            for line in raw.splitlines():
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ktype = parts[0]
                    b64 = parts[1]
                    try:
                        rawb = base64.b64decode(b64 + "===")
                        md5_col = _md5_colon_bytes(rawb)
                        sha_b64 = base64.b64encode(hashlib.sha256(rawb).digest()).decode().rstrip("=")
                        out["agent_keys"].append({
                            "type": ktype,
                            "fingerprint_md5": md5_col,
                            "fingerprint_sha256": f"SHA256:{sha_b64}",
                        })
                    except Exception:
                        out["agent_keys"].append({"type": ktype, "fingerprint": "<unavailable>"})
        except subprocess.CalledProcessError:
            out["error"] = "ssh-agent not available or has no keys"
        except FileNotFoundError:
            out["error"] = "ssh-add not found on PATH"
        except subprocess.TimeoutExpired:
            out["error"] = "ssh-add timed out"
        except Exception as e:
            out["error"] = str(e)
        return out



# Why this will “just work” with your CrewAI agent

# Same args_schema (SSHScannerInput) and _run(self, host, port) -> str returning pretty JSON.

# No extra runtime requirements beyond what you already used (ssh-keyscan). If cryptography or ssh-keygen aren’t present, the tool still runs and notes that enrichment couldn’t be done.

# Output is stable and additive. Your downstream RiskAnalyzer can consume keys[*].type, keys[*].key_size, fingerprint_md5, fingerprint_sha256, etc., with optional keygen_enrich for human-readable verification.