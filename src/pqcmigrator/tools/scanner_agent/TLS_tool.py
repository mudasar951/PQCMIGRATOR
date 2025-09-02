#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ssl
import socket
import subprocess
import json
import re
import hashlib
import ipaddress
from datetime import datetime, timezone
from shutil import which
from typing import Any, Dict, List, Optional, Tuple, Type

# Optional: only used if installed (you already used it in your previous class)
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
except Exception:  # pragma: no cover
    x509 = None
    default_backend = None  # type: ignore

# ---------- CrewAI / Pydantic base tool interfaces ----------
from pydantic import BaseModel, Field
try:
    # CrewAI v0.36+ (BaseTool moved)
    from crewai.tools import BaseTool  # type: ignore
except Exception:
    # Fallback to langchain-style BaseTool if needed
    from langchain.tools import BaseTool  # type: ignore


# =========================
# Helpers (pure functions)
# =========================

def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def resolve_first_ip(host: str) -> Optional[str]:
    try:
        # Prefer AF_INET first, fall back to anything
        infos = socket.getaddrinfo(host, None)
        for fam, _, _, _, sockaddr in infos:
            if fam in (socket.AF_INET, socket.AF_INET6):
                return sockaddr[0]
    except Exception:
        pass
    return None

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha1_hex(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def md5_hex(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def format_md5_colon(der: bytes) -> str:
    h = md5_hex(der)
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))

def format_sha256(der: bytes) -> str:
    return sha256_hex(der)

OPENSSL_BIN = which("openssl")


# =========================
# Pydantic schema for CrewAI
# =========================

class TLSScannerInput(BaseModel):
    host: str = Field(..., description="Target hostname or IP to scan.")
    port: int = Field(default=443, description="TLS port to scan.")


# =========================
# Main Tool
# =========================

class TLSScannerTool(BaseTool):
    """
    CrewAI-compatible tool that performs a rich TLS scan on a single host:port.

    - Tries handshakes for TLSv1.0/1.1/1.2/1.3 (records supported versions, cipher, ALPN, compression)
    - Extracts leaf certificate fingerprints (sha256/sha1) and (optionally) leaf PEM once
    - If OpenSSL is available:
        * Gets negotiated group / KEM hints for TLS 1.3 via `openssl s_client -tls1_3 -msg -tlsextdebug -brief`
        * Extracts full certificate chain PEMs + sha256 and OCSP line via `openssl s_client -showcerts`
        * Decodes leaf cert fields via `openssl x509 -text` (subject, issuer, serial, dates, SAN, CT SCTs)
    - If `cryptography` is installed, extracts leaf public key type and size.
    """
    name: str = "TLSScannerTool"
    description: str = "Scans a host for TLS protocol details, leaf certificate & chain, ALPN, negotiated group, and KEM hints."
    args_schema: Type[BaseModel] = TLSScannerInput

    # ---------- Configurable timeouts ----------
    timeout: int = 5        # TCP connect + OpenSSL s_client overall (sec)
    read_timeout: int = 5   # post-handshake read timeout (sec)
    openssl_enrich: bool = True  # Toggle OpenSSL enrichment

    # ---------- TLS version labels ----------
    TLS_VERSION_LABELS = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    # =========================
    # Public entry (CrewAI)
    # =========================
    def _run(self, host: str, port: int) -> str:
        try:
            result = self.scan_port(host, int(port))
        except Exception as e:
            # last-ditch safety net
            result = {
                "host": host,
                "port": port,
                "timestamp_utc": now_utc_iso(),
                "error": f"{type(e).__name__}: {e}",
            }
        return json.dumps(result, indent=2)

    # =========================
    # Core scanning pipeline
    # =========================

    @staticmethod
    def _make_ctx(ver_enum: ssl.TLSVersion) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ver_enum
        ctx.maximum_version = ver_enum
        # Opportunistically advertise ALPN (common)
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        return ctx

    def _single_handshake(
        self,
        host: str,
        ip: str,
        port: int,
        ver_name: str,
        ver_enum: ssl.TLSVersion,
    ) -> Tuple[str, Dict[str, Any]]:
        info: Dict[str, Any] = {}
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=self.timeout)
            sock.settimeout(self.read_timeout)
            ctx = self._make_ctx(ver_enum)
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                c = ssock.cipher()
                if c:
                    info["negotiated_cipher"] = c[0]
                    info["negotiated_protocol"] = c[1]
                    info["secret_bits"] = c[2]
                else:
                    info["negotiated_cipher"] = None
                    info["negotiated_protocol"] = ver_name
                    info["secret_bits"] = None

                info["compression"] = ssock.compression()
                info["alpn"] = None
                try:
                    info["alpn"] = ssock.selected_alpn_protocol()
                except Exception:
                    pass

                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    info["certificate_fingerprints"] = {
                        "sha256": sha256_hex(cert_der),
                        "sha1": sha1_hex(cert_der),
                    }
                    # Stash leaf PEM only once at object-level
                    if not hasattr(self, "_last_leaf_pem"):
                        try:
                            self._last_leaf_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                        except Exception:
                            self._last_leaf_pem = None

                # KX/auth guess from cipher (TLS 1.2 and below). TLS 1.3 handled separately.
                if ver_enum == ssl.TLSVersion.TLSv1_3:
                    info["kx_guess"] = {
                        "kx": "ECDHE (TLS 1.3 key share)",
                        "auth": "Certificate-based",
                        "note": None,
                    }
                else:
                    cname = info.get("negotiated_cipher") or ""
                    kx = "ECDHE" if "ECDHE" in cname else ("DHE" if "DHE" in cname else ("RSA" if "RSA" in cname else None))
                    auth = "ECDSA" if "ECDSA" in cname else ("RSA" if "RSA" in cname else None)
                    info["kx_guess"] = {"kx": kx, "auth": auth, "note": None}

        except Exception as e:
            info["error"] = f"{type(e).__name__}: {e}"
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
        return (ver_name, info)

    # ---------- OpenSSL helpers ----------

    @staticmethod
    def _run_cmd(cmd: List[str], input_bytes: bytes = b"", timeout: int = 8) -> Tuple[int, str]:
        try:
            p = subprocess.run(
                cmd,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
            out = p.stdout.decode("utf-8", errors="replace")
            return (p.returncode, out)
        except subprocess.TimeoutExpired:
            return (124, "")
        except Exception as e:
            return (1, f"{type(e).__name__}: {e}")

    def _openssl_s_client_tls13(self, host: str, port: int) -> Dict[str, Optional[str]]:
        if not self.openssl_enrich or not OPENSSL_BIN:
            return {}
        cmd = [
            OPENSSL_BIN, "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-tls1_3",
            "-brief",
            "-tlsextdebug",
            "-msg",
        ]
        _, out = self._run_cmd(cmd, timeout=self.timeout)

        group = None
        for pat in [
            r"Negotiated TLS1\.3 group:\s*([A-Za-z0-9_\-]+)",
            r"selected group:\s*([A-Za-z0-9_\-]+)",
            r"Server Temp Key:\s*([A-Za-z0-9_\-]+)",
            r"TLSv1\.3,? key share:\s*([A-Za-z0-9_\-]+)",
        ]:
            m = re.search(pat, out, flags=re.IGNORECASE)
            if m:
                group = m.group(1)
                break

        sig_type = None
        m = re.search(r"Signature type:\s*([A-Za-z0-9_\-]+)", out, flags=re.IGNORECASE)
        if m:
            sig_type = m.group(1)

        alpn = None
        m = re.search(r"ALPN protocol:\s*([A-Za-z0-9\-\._]+)", out, flags=re.IGNORECASE)
        if m:
            alpn = m.group(1)

        kem = None
        if group:
            km = re.search(r"(MLKEM|KYBER|KEM)(?:[_\-]?)(\d+)", group, flags=re.IGNORECASE)
            if km:
                kem = {"name": km.group(1).upper(), "size": int(km.group(2)), "source": "openssl s_client"}

        return {
            "openssl_raw": out,
            "negotiated_group": group,
            "server_signature_type": sig_type,
            "alpn": alpn,
            "kem": kem,
        }

    def _openssl_showcerts(self, host: str, port: int) -> Dict[str, Any]:
        if not self.openssl_enrich or not OPENSSL_BIN:
            return {}
        cmd = [
            OPENSSL_BIN, "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-showcerts",
            "-brief",
        ]
        _, out = self._run_cmd(cmd, timeout=self.timeout)
        pems = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", out)
        chain = []
        for pem in pems:
            try:
                der = ssl.PEM_cert_to_DER_cert(pem)
                chain.append({"sha256": sha256_hex(der), "pem": pem})
            except Exception:
                chain.append({"pem": pem})
        ocsp = None
        m = re.search(r"OCSP response:\s*([^\n\r]+)", out, flags=re.IGNORECASE)
        if m:
            ocsp = m.group(1).strip()
        return {"chain": chain if chain else None, "ocsp": ocsp}

    def _openssl_cert_text(self, pem: str) -> Dict[str, Any]:
        """Decode subject/issuer/dates/SAN/signature alg and CT SCTs using `openssl x509 -text`."""
        if not self.openssl_enrich or not OPENSSL_BIN or not pem:
            return {}
        cmd = [
            OPENSSL_BIN, "x509",
            "-noout",
            "-text",
            "-fingerprint", "-sha256",
            "-issuer",
            "-subject",
            "-serial",
            "-dates",
            "-ext", "subjectAltName",
        ]
        _, out = self._run_cmd(cmd, input_bytes=pem.encode("utf-8"), timeout=self.read_timeout)

        def _line(pattern: str) -> Optional[str]:
            m = re.search(pattern, out)
            return m.group(1).strip() if m else None

        subj = _line(r"Subject:\s*(.+)")
        issuer = _line(r"Issuer:\s*(.+)")
        serial = _line(r"Serial Number:\s*([0-9A-Fa-f:]+)")
        not_before = _line(r"Not Before:\s*(.+)")
        not_after = _line(r"Not After\s?:\s*(.+)")

        san_dns = re.findall(r"DNS:([^\s,]+)", out)
        san_ip = re.findall(r"IP Address:([^\s,]+)", out)
        sig_alg = _line(r"Signature Algorithm:\s*([A-Za-z0-9\-\._]+)")

        # CT Precert SCTs (best-effort)
        scts = []
        mm = re.search(r"CT Precertificate SCTs:\s*(.*?)\n\s*(?:X509v3|Signature Algorithm:)", out, flags=re.DOTALL)
        if mm:
            block = mm.group(1)
            entries = re.split(r"Signed Certificate Timestamp", block, flags=re.IGNORECASE)
            for e in entries:
                # scope the search to each e
                log_id_m = re.search(r"Log ID:\s*([0-9A-F:\s]+)", e)
                log_name_m = re.search(r"Log Name:\s*([^\n\r]+)", e)
                status = "Verified" if re.search(r"Verified", e or "", re.IGNORECASE) else None
                log_id = (log_id_m.group(1) if log_id_m else "").replace(":", "").replace(" ", "")
                log_name = log_name_m.group(1).strip() if log_name_m else None
                if log_id or log_name or status:
                    scts.append({
                        "log_id": log_id or None,
                        "log_name": log_name,
                        "status": status,
                    })

        return {
            "subject": {"raw": subj} if subj else {},
            "issuer": {"raw": issuer} if issuer else {},
            "serial_number_hex": serial.replace(":", "").lower() if serial else None,
            "not_before": not_before,
            "not_after": not_after,
            "san": {"dns": san_dns, "ip": san_ip},
            "signature_algorithm_name": sig_alg,
            "ct": (scts or None),
        }

    # =========================
    # High-level: scan a single port
    # =========================
    def scan_port(self, host: str, port: int) -> Dict[str, Any]:
        # Reset leaf stash (for repeated tool calls)
        if hasattr(self, "_last_leaf_pem"):
            try:
                delattr(self, "_last_leaf_pem")
            except Exception:
                pass

        ip = host if is_ip(host) else (resolve_first_ip(host) or host)
        result: Dict[str, Any] = {
            "host": host,
            "ip": ip,
            "port": int(port),
            "timestamp_utc": now_utc_iso(),
            "tls": {"handshakes": {}, "supported_versions": []},
            "certificate": None,   # enriched leaf
            "chain": None,         # PEMs + sha256 (if openssl)
            "kem": None,           # TLS 1.3 KEM hint (if any)
            "negotiated_group": None,  # TLS 1.3 group / key share
            "ocsp": None,          # OCSP line from s_client
            "ct": None,            # CT SCTs (if available)
            "errors": [],
            "notes": [],
        }

        # Attempt handshakes for each version
        for ver_name, ver_enum in self.TLS_VERSION_LABELS:
            vname, info = self._single_handshake(host, ip, int(port), ver_name, ver_enum)
            if info and "error" not in info:
                result["tls"]["supported_versions"].append(ver_name)
            else:
                if info and info.get("error"):
                    result["errors"].append(f"{ver_name}: {info['error']}")
            result["tls"]["handshakes"][ver_name] = info

        # Promote single, top-level leaf PEM (avoid duplication inside handshakes)
        leaf_pem = getattr(self, "_last_leaf_pem", None)
        if leaf_pem:
            # Start with minimal structure
            result["certificate"] = {
                "subject": {},
                "issuer": {},
                "serial_number_hex": None,
                "not_before": None,
                "not_after": None,
                "san": {"dns": [], "ip": []},
                "fingerprints": None,  # (optional) could compute again from PEM -> DER
                "pem": leaf_pem,
                "signature_algorithm_oid": None,
                "signature_algorithm_name": None,
                "public_key_algorithm_oid": None,
                "public_key_type": None,
                "public_key_size": None,
            }

            # Enrich with openssl x509 -text (if available)
            try:
                xt = self._openssl_cert_text(leaf_pem)
                for k in ("subject", "issuer", "serial_number_hex", "not_before", "not_after", "san", "signature_algorithm_name"):
                    if xt.get(k) is not None:
                        result["certificate"][k] = xt[k]
                if xt.get("ct"):
                    result["ct"] = xt["ct"]
            except Exception:
                pass

            # If cryptography is available, extract public key info
            if x509 and default_backend:
                try:
                    cert = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"), default_backend())
                    pubkey = cert.public_key()
                    result["certificate"]["public_key_type"] = pubkey.__class__.__name__
                    if hasattr(pubkey, "key_size"):
                        result["certificate"]["public_key_size"] = getattr(pubkey, "key_size", None)
                except Exception:
                    pass

        # Optional OpenSSL enrichment: negotiated group / KEM / chain / OCSP / ALPN fallback
        if self.openssl_enrich and OPENSSL_BIN:
            try:
                scli = self._openssl_s_client_tls13(host, int(port))
                if scli:
                    if scli.get("negotiated_group"):
                        result["negotiated_group"] = scli["negotiated_group"]
                        # also stash inside TLSv1.3 handshake node
                        t13 = result["tls"]["handshakes"].get("TLSv1.3", {}) or {}
                        t13["negotiated_group"] = scli["negotiated_group"]
                        result["tls"]["handshakes"]["TLSv1.3"] = t13
                    if scli.get("kem"):
                        result["kem"] = scli["kem"]
                    if scli.get("server_signature_type"):
                        t13 = result["tls"]["handshakes"].get("TLSv1.3", {}) or {}
                        t13["server_signature_type"] = scli["server_signature_type"]
                        result["tls"]["handshakes"]["TLSv1.3"] = t13
                    # If Python didn't expose ALPN, fill from OpenSSL
                    if scli.get("alpn"):
                        for v in result["tls"]["handshakes"].values():
                            if v and v.get("alpn") is None:
                                v["alpn"] = scli["alpn"]
            except Exception:
                pass

            try:
                chain_info = self._openssl_showcerts(host, int(port))
                if chain_info:
                    if chain_info.get("chain"):
                        result["chain"] = chain_info["chain"]
                    if chain_info.get("ocsp"):
                        result["ocsp"] = chain_info["ocsp"]
            except Exception:
                pass

        # Small convenience: if any handshake captured a cert fingerprint but no top-level fingerprints,
        # you can copy one up (optional). We’ll leave as-is to avoid duplication.

        return result





# Notes & compatibility highlights

# You can keep calling this tool exactly like your previous TLSScannerTool through CrewAI; _run() still returns a pretty JSON string.

# If openssl isn’t present, OpenSSL-based enrichment is skipped gracefully.

# If cryptography isn’t installed, public key fields are just left None.

# Timeouts are conservative (timeout=5, read_timeout=5); tweak the class attributes if you need longer scans.

# The result JSON is stable and additive: your existing consumers (risk analyzer, planner) can keep using earlier fields while gaining the new ones (tls.handshakes, tls.supported_versions, alpn, negotiated_group, kem, chain, ocsp, ct, etc.).