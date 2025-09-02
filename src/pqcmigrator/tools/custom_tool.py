# from crewai.tools import BaseTool
# from typing import Type
# from pydantic import BaseModel, Field
# import subprocess
# import socket
# import ssl
# import hashlib
# import os
# import base64
# import re
# import json
# from datetime import datetime

# # cryptography for deep parsing
# from cryptography import x509
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.backends import default_backend


# # ======================================================
# # Utility functions
# # ======================================================
# def format_md5_colon(raw: bytes) -> str:
#     md5 = hashlib.md5(raw).hexdigest()
#     return ":".join(md5[i:i+2] for i in range(0, len(md5), 2))

# def format_sha256(raw: bytes) -> str:
#     return base64.b64encode(hashlib.sha256(raw).digest()).decode()


# # ======================================================
# # Scanner Agent Tools
# # ======================================================

# # ------------------------- TLS ------------------------
# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import ssl
# import socket
# import subprocess
# import json
# import re
# import hashlib
# import ipaddress
# from datetime import datetime, timezone
# from shutil import which
# from typing import Any, Dict, List, Optional, Tuple, Type

# # Optional: only used if installed (you already used it in your previous class)
# try:
#     from cryptography.hazmat.backends import default_backend
#     from cryptography import x509
# except Exception:  # pragma: no cover
#     x509 = None
#     default_backend = None  # type: ignore

# # ---------- CrewAI / Pydantic base tool interfaces ----------
# from pydantic import BaseModel, Field
# try:
#     # CrewAI v0.36+ (BaseTool moved)
#     from crewai.tools import BaseTool  # type: ignore
# except Exception:
#     # Fallback to langchain-style BaseTool if needed
#     from langchain.tools import BaseTool  # type: ignore


# # =========================
# # Helpers (pure functions)
# # =========================

# def is_ip(host: str) -> bool:
#     try:
#         ipaddress.ip_address(host)
#         return True
#     except Exception:
#         return False

# def resolve_first_ip(host: str) -> Optional[str]:
#     try:
#         # Prefer AF_INET first, fall back to anything
#         infos = socket.getaddrinfo(host, None)
#         for fam, _, _, _, sockaddr in infos:
#             if fam in (socket.AF_INET, socket.AF_INET6):
#                 return sockaddr[0]
#     except Exception:
#         pass
#     return None

# def now_utc_iso() -> str:
#     return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# def sha256_hex(b: bytes) -> str:
#     return hashlib.sha256(b).hexdigest()

# def sha1_hex(b: bytes) -> str:
#     return hashlib.sha1(b).hexdigest()

# def md5_hex(b: bytes) -> str:
#     return hashlib.md5(b).hexdigest()

# def format_md5_colon(der: bytes) -> str:
#     h = md5_hex(der)
#     return ":".join(h[i:i+2] for i in range(0, len(h), 2))

# def format_sha256(der: bytes) -> str:
#     return sha256_hex(der)

# OPENSSL_BIN = which("openssl")


# # =========================
# # Pydantic schema for CrewAI
# # =========================

# class TLSScannerInput(BaseModel):
#     host: str = Field(..., description="Target hostname or IP to scan.")
#     port: int = Field(default=443, description="TLS port to scan.")


# # =========================
# # Main Tool
# # =========================

# class TLSScannerTool(BaseTool):
#     """
#     CrewAI-compatible tool that performs a rich TLS scan on a single host:port.

#     - Tries handshakes for TLSv1.0/1.1/1.2/1.3 (records supported versions, cipher, ALPN, compression)
#     - Extracts leaf certificate fingerprints (sha256/sha1) and (optionally) leaf PEM once
#     - If OpenSSL is available:
#         * Gets negotiated group / KEM hints for TLS 1.3 via `openssl s_client -tls1_3 -msg -tlsextdebug -brief`
#         * Extracts full certificate chain PEMs + sha256 and OCSP line via `openssl s_client -showcerts`
#         * Decodes leaf cert fields via `openssl x509 -text` (subject, issuer, serial, dates, SAN, CT SCTs)
#     - If `cryptography` is installed, extracts leaf public key type and size.
#     """
#     name: str = "TLSScannerTool"
#     description: str = "Scans a host for TLS protocol details, leaf certificate & chain, ALPN, negotiated group, and KEM hints."
#     args_schema: Type[BaseModel] = TLSScannerInput

#     # ---------- Configurable timeouts ----------
#     timeout: int = 5        # TCP connect + OpenSSL s_client overall (sec)
#     read_timeout: int = 5   # post-handshake read timeout (sec)
#     openssl_enrich: bool = True  # Toggle OpenSSL enrichment

#     # ---------- TLS version labels ----------
#     TLS_VERSION_LABELS = [
#         ("TLSv1.0", ssl.TLSVersion.TLSv1),
#         ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
#         ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
#         ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
#     ]

#     # =========================
#     # Public entry (CrewAI)
#     # =========================
#     def _run(self, host: str, port: int) -> str:
#         try:
#             result = self.scan_port(host, int(port))
#         except Exception as e:
#             # last-ditch safety net
#             result = {
#                 "host": host,
#                 "port": port,
#                 "timestamp_utc": now_utc_iso(),
#                 "error": f"{type(e).__name__}: {e}",
#             }
#         return json.dumps(result, indent=2)

#     # =========================
#     # Core scanning pipeline
#     # =========================

#     @staticmethod
#     def _make_ctx(ver_enum: ssl.TLSVersion) -> ssl.SSLContext:
#         ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#         ctx.check_hostname = False
#         ctx.verify_mode = ssl.CERT_NONE
#         ctx.minimum_version = ver_enum
#         ctx.maximum_version = ver_enum
#         # Opportunistically advertise ALPN (common)
#         try:
#             ctx.set_alpn_protocols(["h2", "http/1.1"])
#         except Exception:
#             pass
#         return ctx

#     def _single_handshake(
#         self,
#         host: str,
#         ip: str,
#         port: int,
#         ver_name: str,
#         ver_enum: ssl.TLSVersion,
#     ) -> Tuple[str, Dict[str, Any]]:
#         info: Dict[str, Any] = {}
#         sock = None
#         try:
#             sock = socket.create_connection((ip, port), timeout=self.timeout)
#             sock.settimeout(self.read_timeout)
#             ctx = self._make_ctx(ver_enum)
#             with ctx.wrap_socket(sock, server_hostname=host) as ssock:
#                 c = ssock.cipher()
#                 if c:
#                     info["negotiated_cipher"] = c[0]
#                     info["negotiated_protocol"] = c[1]
#                     info["secret_bits"] = c[2]
#                 else:
#                     info["negotiated_cipher"] = None
#                     info["negotiated_protocol"] = ver_name
#                     info["secret_bits"] = None

#                 info["compression"] = ssock.compression()
#                 info["alpn"] = None
#                 try:
#                     info["alpn"] = ssock.selected_alpn_protocol()
#                 except Exception:
#                     pass

#                 cert_der = ssock.getpeercert(binary_form=True)
#                 if cert_der:
#                     info["certificate_fingerprints"] = {
#                         "sha256": sha256_hex(cert_der),
#                         "sha1": sha1_hex(cert_der),
#                     }
#                     # Stash leaf PEM only once at object-level
#                     if not hasattr(self, "_last_leaf_pem"):
#                         try:
#                             self._last_leaf_pem = ssl.DER_cert_to_PEM_cert(cert_der)
#                         except Exception:
#                             self._last_leaf_pem = None

#                 # KX/auth guess from cipher (TLS 1.2 and below). TLS 1.3 handled separately.
#                 if ver_enum == ssl.TLSVersion.TLSv1_3:
#                     info["kx_guess"] = {
#                         "kx": "ECDHE (TLS 1.3 key share)",
#                         "auth": "Certificate-based",
#                         "note": None,
#                     }
#                 else:
#                     cname = info.get("negotiated_cipher") or ""
#                     kx = "ECDHE" if "ECDHE" in cname else ("DHE" if "DHE" in cname else ("RSA" if "RSA" in cname else None))
#                     auth = "ECDSA" if "ECDSA" in cname else ("RSA" if "RSA" in cname else None)
#                     info["kx_guess"] = {"kx": kx, "auth": auth, "note": None}

#         except Exception as e:
#             info["error"] = f"{type(e).__name__}: {e}"
#         finally:
#             try:
#                 if sock:
#                     sock.close()
#             except Exception:
#                 pass
#         return (ver_name, info)

#     # ---------- OpenSSL helpers ----------

#     @staticmethod
#     def _run_cmd(cmd: List[str], input_bytes: bytes = b"", timeout: int = 8) -> Tuple[int, str]:
#         try:
#             p = subprocess.run(
#                 cmd,
#                 input=input_bytes,
#                 stdout=subprocess.PIPE,
#                 stderr=subprocess.STDOUT,
#                 timeout=timeout,
#                 check=False,
#             )
#             out = p.stdout.decode("utf-8", errors="replace")
#             return (p.returncode, out)
#         except subprocess.TimeoutExpired:
#             return (124, "")
#         except Exception as e:
#             return (1, f"{type(e).__name__}: {e}")

#     def _openssl_s_client_tls13(self, host: str, port: int) -> Dict[str, Optional[str]]:
#         if not self.openssl_enrich or not OPENSSL_BIN:
#             return {}
#         cmd = [
#             OPENSSL_BIN, "s_client",
#             "-connect", f"{host}:{port}",
#             "-servername", host,
#             "-tls1_3",
#             "-brief",
#             "-tlsextdebug",
#             "-msg",
#         ]
#         _, out = self._run_cmd(cmd, timeout=self.timeout)

#         group = None
#         for pat in [
#             r"Negotiated TLS1\.3 group:\s*([A-Za-z0-9_\-]+)",
#             r"selected group:\s*([A-Za-z0-9_\-]+)",
#             r"Server Temp Key:\s*([A-Za-z0-9_\-]+)",
#             r"TLSv1\.3,? key share:\s*([A-Za-z0-9_\-]+)",
#         ]:
#             m = re.search(pat, out, flags=re.IGNORECASE)
#             if m:
#                 group = m.group(1)
#                 break

#         sig_type = None
#         m = re.search(r"Signature type:\s*([A-Za-z0-9_\-]+)", out, flags=re.IGNORECASE)
#         if m:
#             sig_type = m.group(1)

#         alpn = None
#         m = re.search(r"ALPN protocol:\s*([A-Za-z0-9\-\._]+)", out, flags=re.IGNORECASE)
#         if m:
#             alpn = m.group(1)

#         kem = None
#         if group:
#             km = re.search(r"(MLKEM|KYBER|KEM)(?:[_\-]?)(\d+)", group, flags=re.IGNORECASE)
#             if km:
#                 kem = {"name": km.group(1).upper(), "size": int(km.group(2)), "source": "openssl s_client"}

#         return {
#             "openssl_raw": out,
#             "negotiated_group": group,
#             "server_signature_type": sig_type,
#             "alpn": alpn,
#             "kem": kem,
#         }

#     def _openssl_showcerts(self, host: str, port: int) -> Dict[str, Any]:
#         if not self.openssl_enrich or not OPENSSL_BIN:
#             return {}
#         cmd = [
#             OPENSSL_BIN, "s_client",
#             "-connect", f"{host}:{port}",
#             "-servername", host,
#             "-showcerts",
#             "-brief",
#         ]
#         _, out = self._run_cmd(cmd, timeout=self.timeout)
#         pems = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", out)
#         chain = []
#         for pem in pems:
#             try:
#                 der = ssl.PEM_cert_to_DER_cert(pem)
#                 chain.append({"sha256": sha256_hex(der), "pem": pem})
#             except Exception:
#                 chain.append({"pem": pem})
#         ocsp = None
#         m = re.search(r"OCSP response:\s*([^\n\r]+)", out, flags=re.IGNORECASE)
#         if m:
#             ocsp = m.group(1).strip()
#         return {"chain": chain if chain else None, "ocsp": ocsp}

#     def _openssl_cert_text(self, pem: str) -> Dict[str, Any]:
#         """Decode subject/issuer/dates/SAN/signature alg and CT SCTs using `openssl x509 -text`."""
#         if not self.openssl_enrich or not OPENSSL_BIN or not pem:
#             return {}
#         cmd = [
#             OPENSSL_BIN, "x509",
#             "-noout",
#             "-text",
#             "-fingerprint", "-sha256",
#             "-issuer",
#             "-subject",
#             "-serial",
#             "-dates",
#             "-ext", "subjectAltName",
#         ]
#         _, out = self._run_cmd(cmd, input_bytes=pem.encode("utf-8"), timeout=self.read_timeout)

#         def _line(pattern: str) -> Optional[str]:
#             m = re.search(pattern, out)
#             return m.group(1).strip() if m else None

#         subj = _line(r"Subject:\s*(.+)")
#         issuer = _line(r"Issuer:\s*(.+)")
#         serial = _line(r"Serial Number:\s*([0-9A-Fa-f:]+)")
#         not_before = _line(r"Not Before:\s*(.+)")
#         not_after = _line(r"Not After\s?:\s*(.+)")

#         san_dns = re.findall(r"DNS:([^\s,]+)", out)
#         san_ip = re.findall(r"IP Address:([^\s,]+)", out)
#         sig_alg = _line(r"Signature Algorithm:\s*([A-Za-z0-9\-\._]+)")

#         # CT Precert SCTs (best-effort)
#         scts = []
#         mm = re.search(r"CT Precertificate SCTs:\s*(.*?)\n\s*(?:X509v3|Signature Algorithm:)", out, flags=re.DOTALL)
#         if mm:
#             block = mm.group(1)
#             entries = re.split(r"Signed Certificate Timestamp", block, flags=re.IGNORECASE)
#             for e in entries:
#                 # scope the search to each e
#                 log_id_m = re.search(r"Log ID:\s*([0-9A-F:\s]+)", e)
#                 log_name_m = re.search(r"Log Name:\s*([^\n\r]+)", e)
#                 status = "Verified" if re.search(r"Verified", e or "", re.IGNORECASE) else None
#                 log_id = (log_id_m.group(1) if log_id_m else "").replace(":", "").replace(" ", "")
#                 log_name = log_name_m.group(1).strip() if log_name_m else None
#                 if log_id or log_name or status:
#                     scts.append({
#                         "log_id": log_id or None,
#                         "log_name": log_name,
#                         "status": status,
#                     })

#         return {
#             "subject": {"raw": subj} if subj else {},
#             "issuer": {"raw": issuer} if issuer else {},
#             "serial_number_hex": serial.replace(":", "").lower() if serial else None,
#             "not_before": not_before,
#             "not_after": not_after,
#             "san": {"dns": san_dns, "ip": san_ip},
#             "signature_algorithm_name": sig_alg,
#             "ct": (scts or None),
#         }

#     # =========================
#     # High-level: scan a single port
#     # =========================
#     def scan_port(self, host: str, port: int) -> Dict[str, Any]:
#         # Reset leaf stash (for repeated tool calls)
#         if hasattr(self, "_last_leaf_pem"):
#             try:
#                 delattr(self, "_last_leaf_pem")
#             except Exception:
#                 pass

#         ip = host if is_ip(host) else (resolve_first_ip(host) or host)
#         result: Dict[str, Any] = {
#             "host": host,
#             "ip": ip,
#             "port": int(port),
#             "timestamp_utc": now_utc_iso(),
#             "tls": {"handshakes": {}, "supported_versions": []},
#             "certificate": None,   # enriched leaf
#             "chain": None,         # PEMs + sha256 (if openssl)
#             "kem": None,           # TLS 1.3 KEM hint (if any)
#             "negotiated_group": None,  # TLS 1.3 group / key share
#             "ocsp": None,          # OCSP line from s_client
#             "ct": None,            # CT SCTs (if available)
#             "errors": [],
#             "notes": [],
#         }

#         # Attempt handshakes for each version
#         for ver_name, ver_enum in self.TLS_VERSION_LABELS:
#             vname, info = self._single_handshake(host, ip, int(port), ver_name, ver_enum)
#             if info and "error" not in info:
#                 result["tls"]["supported_versions"].append(ver_name)
#             else:
#                 if info and info.get("error"):
#                     result["errors"].append(f"{ver_name}: {info['error']}")
#             result["tls"]["handshakes"][ver_name] = info

#         # Promote single, top-level leaf PEM (avoid duplication inside handshakes)
#         leaf_pem = getattr(self, "_last_leaf_pem", None)
#         if leaf_pem:
#             # Start with minimal structure
#             result["certificate"] = {
#                 "subject": {},
#                 "issuer": {},
#                 "serial_number_hex": None,
#                 "not_before": None,
#                 "not_after": None,
#                 "san": {"dns": [], "ip": []},
#                 "fingerprints": None,  # (optional) could compute again from PEM -> DER
#                 "pem": leaf_pem,
#                 "signature_algorithm_oid": None,
#                 "signature_algorithm_name": None,
#                 "public_key_algorithm_oid": None,
#                 "public_key_type": None,
#                 "public_key_size": None,
#             }

#             # Enrich with openssl x509 -text (if available)
#             try:
#                 xt = self._openssl_cert_text(leaf_pem)
#                 for k in ("subject", "issuer", "serial_number_hex", "not_before", "not_after", "san", "signature_algorithm_name"):
#                     if xt.get(k) is not None:
#                         result["certificate"][k] = xt[k]
#                 if xt.get("ct"):
#                     result["ct"] = xt["ct"]
#             except Exception:
#                 pass

#             # If cryptography is available, extract public key info
#             if x509 and default_backend:
#                 try:
#                     cert = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"), default_backend())
#                     pubkey = cert.public_key()
#                     result["certificate"]["public_key_type"] = pubkey.__class__.__name__
#                     if hasattr(pubkey, "key_size"):
#                         result["certificate"]["public_key_size"] = getattr(pubkey, "key_size", None)
#                 except Exception:
#                     pass

#         # Optional OpenSSL enrichment: negotiated group / KEM / chain / OCSP / ALPN fallback
#         if self.openssl_enrich and OPENSSL_BIN:
#             try:
#                 scli = self._openssl_s_client_tls13(host, int(port))
#                 if scli:
#                     if scli.get("negotiated_group"):
#                         result["negotiated_group"] = scli["negotiated_group"]
#                         # also stash inside TLSv1.3 handshake node
#                         t13 = result["tls"]["handshakes"].get("TLSv1.3", {}) or {}
#                         t13["negotiated_group"] = scli["negotiated_group"]
#                         result["tls"]["handshakes"]["TLSv1.3"] = t13
#                     if scli.get("kem"):
#                         result["kem"] = scli["kem"]
#                     if scli.get("server_signature_type"):
#                         t13 = result["tls"]["handshakes"].get("TLSv1.3", {}) or {}
#                         t13["server_signature_type"] = scli["server_signature_type"]
#                         result["tls"]["handshakes"]["TLSv1.3"] = t13
#                     # If Python didn't expose ALPN, fill from OpenSSL
#                     if scli.get("alpn"):
#                         for v in result["tls"]["handshakes"].values():
#                             if v and v.get("alpn") is None:
#                                 v["alpn"] = scli["alpn"]
#             except Exception:
#                 pass

#             try:
#                 chain_info = self._openssl_showcerts(host, int(port))
#                 if chain_info:
#                     if chain_info.get("chain"):
#                         result["chain"] = chain_info["chain"]
#                     if chain_info.get("ocsp"):
#                         result["ocsp"] = chain_info["ocsp"]
#             except Exception:
#                 pass

#         # Small convenience: if any handshake captured a cert fingerprint but no top-level fingerprints,
#         # you can copy one up (optional). We’ll leave as-is to avoid duplication.

#         return result


# # Notes & compatibility highlights

# # You can keep calling this tool exactly like your previous TLSScannerTool through CrewAI; _run() still returns a pretty JSON string.

# # If openssl isn’t present, OpenSSL-based enrichment is skipped gracefully.

# # If cryptography isn’t installed, public key fields are just left None.

# # Timeouts are conservative (timeout=5, read_timeout=5); tweak the class attributes if you need longer scans.

# # The result JSON is stable and additive: your existing consumers (risk analyzer, planner) can keep using earlier fields while gaining the new ones (tls.handshakes, tls.supported_versions, alpn, negotiated_group, kem, chain, ocsp, ct, etc.).


# # ------------------------- SSH ------------------------
# import subprocess, json, base64, hashlib
# from typing import Type
# from pydantic import BaseModel, Field
# from cryptography.hazmat.primitives.serialization import load_ssh_public_key
# from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

# # --- helpers --------------------------------------------------------

# def _md5_colon_from_b64(key_b64: str) -> str:
#     """OpenSSH-style MD5 fingerprint as colon-separated hex of the raw key blob."""
#     blob = base64.b64decode(key_b64.encode())
#     h = hashlib.md5(blob).hexdigest()
#     return ":".join(h[i:i+2] for i in range(0, len(h), 2))

# def _sha256_from_b64(key_b64: str) -> str:
#     """OpenSSH-style SHA256 fingerprint (Base64, no padding)."""
#     blob = base64.b64decode(key_b64.encode())
#     fp = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
#     return f"SHA256:{fp}"

# def _key_size_from_pubkey_obj(pubkey) -> int | None:
#     if isinstance(pubkey, rsa.RSAPublicKey):
#         return pubkey.key_size
#     if isinstance(pubkey, ec.EllipticCurvePublicKey):
#         return pubkey.curve.key_size  # e.g., 256 for nistp256
#     if isinstance(pubkey, ed25519.Ed25519PublicKey):
#         return 256  # Ed25519 keys are 256-bit
#     return None

# # --- tool -----------------------------------------------------------

# class SSHScannerInput(BaseModel):
#     host: str = Field(..., description="Target hostname or IP for SSH scan.")
#     port: int = Field(default=22, description="SSH port, usually 22.")

# class SSHScannerTool(BaseTool):
#     name: str = "SSHScannerTool"
#     description: str = "Scans a host using ssh-keyscan to retrieve SSH key details (algorithm, size, fingerprints)."
#     args_schema: Type[BaseModel] = SSHScannerInput

#     def _run(self, host: str, port: int) -> str:
#         """
#         Uses `ssh-keyscan` to fetch host public keys and derives:
#           - algorithm (type)
#           - key_size (bits)
#           - fingerprint_md5 (OpenSSH colon-hex)
#           - fingerprint_sha256 (OpenSSH Base64 form without '=' padding)
#         """
#         result = {"host": host, "port": port, "keys": []}
#         try:
#             # -T 5 sets a 5s per-host timeout; adjust if you need longer.
#             # We don't restrict -t (type) so we capture whatever the server offers.
#             cmd = ["ssh-keyscan", "-T", "5", "-p", str(port), host]
#             output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

#             lines = [ln for ln in output.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
#             if not lines:
#                 result["error"] = "No SSH keys found or ssh-keyscan returned no usable output."
#                 return json.dumps(result, indent=2)

#             for line in lines:
#                 # Expected: "<host> <type> <base64> [comment]"
#                 parts = line.strip().split()
#                 if len(parts) < 3:
#                     # keep raw line for debugging
#                     result["keys"].append({"type": None, "error": f"Invalid line format: {line}"})
#                     continue

#                 # host_token can be hashed like |1|..., we don't rely on it.
#                 _host_token = parts[0]
#                 key_type = parts[1]
#                 key_b64 = parts[2]
#                 comment = " ".join(parts[3:]) if len(parts) > 3 else ""

#                 try:
#                     # cryptography expects the OpenSSH "type base64" form (not the raw decoded blob)
#                     pubkey = load_ssh_public_key(f"{key_type} {key_b64}".encode())

#                     key_size = _key_size_from_pubkey_obj(pubkey)
#                     fp_md5 = _md5_colon_from_b64(key_b64)
#                     fp_sha256 = _sha256_from_b64(key_b64)

#                     result["keys"].append({
#                         "type": key_type,
#                         "key_size": key_size,
#                         "fingerprint_md5": fp_md5,
#                         "fingerprint_sha256": fp_sha256,
#                         "comment": comment or None,
#                         "source": "ssh-keyscan"
#                     })
#                 except Exception as ex:
#                     # Include minimal context to help debug parsing issues.
#                     result["keys"].append({
#                         "type": key_type,
#                         "error": f"Key parse failed: {ex.__class__.__name__}: {str(ex)}",
#                         "raw_line": line
#                     })

#         except subprocess.CalledProcessError as e:
#             result["error"] = f"ssh-keyscan failed: {e.output}"
#         except FileNotFoundError:
#             result["error"] = "ssh-keyscan is not installed or not in PATH."
#         except Exception as e:
#             result["error"] = f"SSH scan failed: {str(e)}"

#         return json.dumps(result, indent=2)



# # ------------------------- Codebase -------------------
# class CodeScannerInput(BaseModel):
#     path: str = Field(..., description="Path to directory or file to scan for secrets and crypto usage.")

# class CodeScannerTool(BaseTool):
#     name: str = "CodeScannerTool"
#     description: str = "Scans code files for secrets, credentials, and weak cryptographic algorithm usage."
#     args_schema: Type[BaseModel] = CodeScannerInput

#     def _run(self, path: str) -> str:
#         result = {"path": path, "findings": []}
#         patterns = [
#             (r"-----BEGIN (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----", "Private Key"),
#             (r"AKIA[0-9A-Z]{16}", "AWS Key ID"),
#             (r"(?i)(api[_-]?key|token)[\"'\s:=]{1,4}[A-Za-z0-9\-\._]{8,}", "API Key or Token"),
#             (r"(?i)password\s*[:=]\s*['\"].{6,}['\"]", "Hardcoded password"),
#             (r"\bssh-rsa\b", "SSH RSA Key"),
#             (r"\bMD5\b", "Weak Algorithm (MD5)"),
#             (r"\bSHA1\b", "Weak Algorithm (SHA1)"),
#             (r"\bDES\b", "Weak Algorithm (DES)"),
#             (r"\bRSA\b", "Potential RSA usage"),
#             (r"\bDSA\b", "Potential DSA usage"),
#         ]

#         try:
#             if os.path.isfile(path):
#                 files = [path]
#             else:
#                 files = []
#                 for root, _, filenames in os.walk(path):
#                     for f in filenames:
#                         files.append(os.path.join(root, f))

#             for file in files:
#                 try:
#                     with open(file, "r", errors="ignore") as f:
#                         content = f.read()
#                         for pattern, label in patterns:
#                             for match in re.finditer(pattern, content):
#                                 result["findings"].append({
#                                     "file": file,
#                                     "label": label,
#                                     "match": match.group(0)[:200]
#                                 })
#                 except Exception:
#                     continue
#         except Exception as e:
#             result["error"] = str(e)
#         return json.dumps(result, indent=2)


# # ------------------------- YARA ------------------------
# class YARAScannerInput(BaseModel):
#     paths: str = Field(..., description="Comma-separated list of file paths to simulate YARA scan.")

# class YARAScannerTool(BaseTool):
#     name: str = "YARAScannerTool"
#     description: str = "Simulated YARA scanner to detect key material. Replace with yara-python for production."
#     args_schema: Type[BaseModel] = YARAScannerInput

#     def _run(self, paths: str) -> str:
#         result = {"paths": paths.split(","), "matches": []}
#         for p in result["paths"]:
#             p = p.strip()
#             if not os.path.exists(p):
#                 result["matches"].append({"file": p, "error": "File not found"})
#                 continue
#             try:
#                 with open(p, "rb") as f:
#                     data = f.read()
#                     if b"PRIVATE" in data or b"KEY" in data:
#                         result["matches"].append({
#                             "file": p,
#                             "match": "Potential key material found"
#                         })
#             except Exception as e:
#                 result["matches"].append({"file": p, "error": str(e)})
#         return json.dumps(result, indent=2)


# # ======================================================
# # Risk Analyzer Agent Tools
# # ======================================================
# import json, re
# from datetime import datetime, timezone, timedelta
# from typing import List, Optional, Dict, Any, Type
# from pydantic import BaseModel, Field
# from enum import Enum

# # ---------------- CONFIG (Q-RESISTANCE FOCUS) ----------------
# # We focus on *quantum* risk (store-now-decrypt-later and future forgery).
# # Classical asymmetric (RSA, DSA, ECDSA/EdDSA incl. Ed25519) ⇒ Broken by Shor (High).
# # Symmetric/hash aren’t host keys/certs here, but if present we’d rate:
# #   AES-128 ~ Medium (Grover), AES-256 ~ Low; SHA-2/3 preimage ~ Medium/Low.
# # TLS hybrid/PQ KEM hints reduce confidentiality risk for KEX to Medium/Low.

# PQC_KEM_HINTS = {"ml-kem", "mlkem", "kyber", "x25519mlkem", "hybrid", "mlkem768", "mlkem1024"}
# TLS1_3_PREFIXES = {"tls1.3", "tls13", "tlsv1.3"}

# # ---------------- MODELS (unchanged inputs) ----------------
# class RiskLevel(str, Enum):
#     Low = "Low"
#     Medium = "Medium"
#     High = "High"
#     Expired = "Expired"

# class TLSFinding(BaseModel):
#     host: Optional[str] = None
#     version: Optional[str] = None                  # e.g., "TLS 1.3"
#     public_key_type: Optional[str] = None          # "RSA", "EC", "ECDSA" etc.
#     public_key_size: Optional[int] = None          # bits
#     signature_algo: Optional[str] = None           # e.g., "ECDSA with SHA-256"
#     cipher: Optional[str] = None                   # e.g., "AES_128_GCM"
#     kem: Optional[str] = None                      # e.g., "X25519MLKEM768"
#     not_valid_after: Optional[str] = None          # ISO 8601

# class SSHFinding(BaseModel):
#     host: Optional[str] = None
#     key_type: Optional[str] = None                 # "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"
#     key_size: Optional[int] = None                 # bits (if available)

# class CodeFinding(BaseModel):
#     file: Optional[str] = None
#     label: Optional[str] = None                    # free text

# class ScanResults(BaseModel):
#     tls: List[TLSFinding] = Field(default_factory=list)
#     ssh: List[SSHFinding] = Field(default_factory=list)
#     codebase: List[CodeFinding] = Field(default_factory=list)

# class RiskAnalyzerInput(BaseModel):
#     scan_results: str = Field(..., description="JSON string of scan results from scanner agent.")

# # ---------------- HELPERS ----------------
# def _norm(s: Optional[str]) -> str:
#     return (s or "").strip()

# def _low(s: Optional[str]) -> str:
#     return _norm(s).lower()

# def _tls_version_tag(version: Optional[str]) -> str:
#     v = _low(version).replace(" ", "")
#     v = v.replace("tlsv", "tls")  # handle "TLSv1.3"
#     return v

# def _has_pqc_kem(s: Optional[str]) -> bool:
#     low = _low(s)
#     return any(k in low for k in PQC_KEM_HINTS)

# def _algo_from_tls_pubkey(t: TLSFinding) -> str:
#     a = _low(t.public_key_type)
#     if not a:
#         # fall back to signature algo if present
#         sig = _low(t.signature_algo)
#         if "rsa" in sig:
#             return "RSA"
#         if "ecdsa" in sig or "ec" in sig:
#             return "ECDSA"
#         if "ed25519" in sig:
#             return "Ed25519"
#         return "Unknown"
#     if a.startswith("rsa"):
#         return "RSA"
#     if a in {"ec", "ecdsa", "ecc"}:
#         return "ECDSA"
#     if "ed25519" in a:
#         return "Ed25519"
#     return t.public_key_type or "Unknown"

# def _algo_from_ssh_keytype(ktype: Optional[str]) -> str:
#     k = _low(ktype)
#     if k.startswith("ssh-rsa"):
#         return "RSA"
#     if k.startswith("ecdsa-"):
#         return "ECDSA"
#     if k.startswith("ssh-ed25519"):
#         return "Ed25519"
#     if k.startswith("sk-"):  # FIDO/U2F backed, but signatures are still classical
#         # e.g., sk-ssh-ed25519@openssh.com
#         if "ed25519" in k:
#             return "Ed25519 (FIDO)"
#         if "ecdsa" in k:
#             return "ECDSA (FIDO)"
#     return ktype or "Unknown"

# # ---------------- QUANTUM-RISK EVALUATION ----------------
# def evaluate_tls_quantum(t: TLSFinding) -> Dict[str, Any]:
#     """
#     PQ-centric evaluation:
#       - Authentication (cert signatures & server long-term key): classical → Shor breaks ⇒ High.
#       - Confidentiality (KEX): if hybrid/PQ KEM detected (e.g., ML-KEM), reduce to Medium/Low.
#       We report a single 'risk' with a reason that explains both aspects briefly.
#     """
#     host = t.host or "(unknown)"
#     alg = _algo_from_tls_pubkey(t)
#     size = t.public_key_size
#     vtag = _tls_version_tag(t.version)
#     kem = t.kem or ""

#     pq_kem = _has_pqc_kem(kem)

#     # Default: High (classical-only)
#     risk = "High"
#     reason_bits = []
#     if alg in {"RSA", "ECDSA", "Ed25519", "Ed25519 (FIDO)", "ECDSA (FIDO)"}:
#         reason_bits.append(f"{alg} signatures are classical—broken by Shor")

#     # KEX consideration (store-now-decrypt-later):
#     if vtag in TLS1_3_PREFIXES:
#         if pq_kem:
#             # Hybrid/PQ KEM mitigates confidentiality (but auth still classical)
#             risk = "Medium"
#             reason_bits.append(f"Hybrid/PQ KEM detected ({t.kem}) for key exchange")
#         else:
#             reason_bits.append("Classical-only key exchange (vulnerable to store-now-decrypt-later)")
#     else:
#         # TLS < 1.3 is classical KEX; keep High
#         reason_bits.append("Non-PQ key exchange")

#     # Add size note (informational only; does not change quantum risk)
#     if size:
#         reason_bits.append(f"cert key size: {size} bits")

#     return {
#         "asset": f"TLS certificate for {host}",
#         "algorithm": alg,
#         "key_size": size,
#         "risk": risk,
#         "reason": "; ".join(reason_bits) or "Classical cryptography; not quantum-resistant"
#     }

# def evaluate_ssh_quantum(s: SSHFinding) -> Dict[str, Any]:
#     """
#     SSH host keys today are classical (RSA/ECDSA/Ed25519). Under Shor, all are breakable.
#     There is no standardized PQC for SSH host authentication yet → High.
#     """
#     host = s.host or "(unknown)"
#     alg = _algo_from_ssh_keytype(s.key_type)
#     size = s.key_size

#     reason_bits = []
#     if alg.startswith("RSA"):
#         reason_bits.append("RSA signatures are classical—broken by Shor")
#     elif alg.startswith("ECDSA"):
#         reason_bits.append("ECDSA (elliptic-curve discrete log) broken by Shor")
#     elif alg.startswith("Ed25519"):
#         reason_bits.append("Ed25519 (elliptic-curve discrete log) broken by Shor")
#     else:
#         reason_bits.append("Unknown/legacy SSH key type (assume classical)")

#     if size:
#         reason_bits.append(f"host key size: {size} bits")

#     return {
#         "asset": f"SSH key on host {host}",
#         "algorithm": alg,
#         "key_size": size,
#         "risk": "High",  # until standardized PQ host keys exist/deployed
#         "reason": "; ".join(reason_bits)
#     }

# def evaluate_code_quantum(c: CodeFinding) -> Dict[str, Any]:
#     """
#     Very coarse PQ lens for code findings (if provided):
#       - If label hints at ML-KEM/Dilithium/SLH-DSA → Low
#       - If label hints at RSA/ECDSA/Ed25519 → High
#       - Else → Medium (unknown posture)
#     """
#     label = _low(c.label)
#     alg = "Unknown"
#     risk = "Medium"
#     reason = "Posture unknown"

#     if any(k in label for k in ("ml-kem", "mlkem", "kyber", "ml-dsa", "dilithium", "slh-dsa", "sphincs")):
#         alg = "PQC"
#         risk = "Low"
#         reason = "Post-quantum primitive referenced"
#     elif any(k in label for k in ("rsa", "ecdsa", "ed25519", "x25519", "ecdh", "ecdsA")):
#         alg = "Classical"
#         risk = "High"
#         reason = "Classical primitive referenced (broken by Shor)"
#     return {
#         "asset": f"Code {c.file or '(unknown)'}",
#         "algorithm": alg,
#         "key_size": None,
#         "risk": risk,
#         "reason": reason if c.label is None else f"{reason}: {c.label}"
#     }

# # ---------------- TOOL (outputs a JSON LIST) ----------------
# class RiskAnalyzerTool(BaseTool):
#     name: str = "RiskAnalyzerTool"
#     description: str = "Evaluates cryptographic assets with a quantum-resistance lens and assigns risk levels."
#     args_schema: Type[BaseModel] = RiskAnalyzerInput

#     def _run(self, scan_results: str) -> str:
#         # Parse input JSON safely into our model
#         try:
#             payload = json.loads(scan_results)
#             data = ScanResults(**payload)
#         except Exception as e:
#             # Output still as a list (with a single error object) to match required format
#             return json.dumps([{
#                 "asset": "parse_error",
#                 "algorithm": "Unknown",
#                 "key_size": None,
#                 "risk": "High",
#                 "reason": f"Invalid input JSON: {str(e)}"
#             }], indent=2)

#         out: List[Dict[str, Any]] = []

#         # TLS findings → PQ view (auth classical, KEX maybe hybrid)
#         for t in data.tls:
#             out.append(evaluate_tls_quantum(t))

#         # SSH host keys → PQ view (all classical today)
#         for s in data.ssh:
#             out.append(evaluate_ssh_quantum(s))

#         # Code findings (optional) → coarse PQ view
#         for c in data.codebase:
#             out.append(evaluate_code_quantum(c))

#         # Return EXACTLY a JSON list as requested
#         return json.dumps(out, indent=2)




# # # ======================================================
# # # Planner Agent Tools
# # # ======================================================
# # class PlannerInput(BaseModel):
# #     risks: str = Field(..., description="JSON string of risk evaluation results.")

# # class PlannerTool(BaseTool):
# #     name: str = "PlannerTool"
# #     description: str = "Creates a PQC migration plan based on risks, mapping classical algorithms to NIST PQC replacements."
# #     args_schema: Type[BaseModel] = PlannerInput

# #     def _run(self, risks: str) -> str:
# #         try:
# #             risk_data = json.loads(risks)
# #         except Exception as e:
# #             return json.dumps({"error": f"Invalid input JSON: {str(e)}"}, indent=2)

# #         pqc_map = {
# #             "RSA": "CRYSTALS-Kyber",
# #             "ECDSA": "Dilithium",
# #             "DSA": "Dilithium",
# #             "SHA1": "SHA3-256",
# #             "MD5": "SHA3-256",
# #         }

# #         plan = []
# #         priority = 1
# #         for asset in risk_data:
# #             algo = asset.get("issue", "RSA")
# #             replacement = pqc_map.get(algo, "SPHINCS+")
# #             plan.append({
# #                 "asset": asset.get("asset"),
# #                 "risk": asset.get("risk"),
# #                 "recommended_replacement": replacement,
# #                 "priority": priority
# #             })
# #             priority += 1

# #         return json.dumps({"plan": plan}, indent=2)


# # # ======================================================
# # # Migrator Agent Tools
# # # ======================================================
# # class MigratorInput(BaseModel):
# #     plan: str = Field(..., description="JSON string migration plan from planner.")

# # class MigratorTool(BaseTool):
# #     name: str = "MigratorTool"
# #     description: str = "Executes the migration plan (simulated) by generating PQC keys/certs and updating configs."
# #     args_schema: Type[BaseModel] = MigratorInput

# #     def _run(self, plan: str) -> str:
# #         try:
# #             plan_data = json.loads(plan)
# #         except Exception as e:
# #             return json.dumps({"error": f"Invalid input JSON: {str(e)}"}, indent=2)

# #         executed, failed = [], []

# #         for item in plan_data.get("plan", []):
# #             asset = item.get("asset")
# #             replacement = item.get("recommended_replacement")
# #             risk = item.get("risk")

# #             if risk == "High":
# #                 executed.append({
# #                     "asset": asset,
# #                     "action": f"Migrated to {replacement}",
# #                     "status": "Success"
# #                 })
# #             else:
# #                 failed.append({
# #                     "asset": asset,
# #                     "reason": "Migration not required or pending manual approval"
# #                 })

# #         return json.dumps({"executed": executed, "failed": failed}, indent=2)


# # # ======================================================
# # # Rollback Agent Tools
# # # ======================================================
# # class RollbackInput(BaseModel):
# #     migration_report: str = Field(..., description="JSON migration execution report from migrator.")

# # class RollbackTool(BaseTool):
# #     name: str = "RollbackTool"
# #     description: str = "Restores system state if migration failed using backups."
# #     args_schema: Type[BaseModel] = RollbackInput

# #     def _run(self, migration_report: str) -> str:
# #         try:
# #             report = json.loads(migration_report)
# #         except Exception as e:
# #             return json.dumps({"error": f"Invalid input JSON: {str(e)}"}, indent=2)

# #         restored = []
# #         if report.get("failed"):
# #             for f in report["failed"]:
# #                 restored.append(f["asset"])

# #         rollback_info = {
# #             "rollback_triggered": bool(restored),
# #             "assets_restored": restored,
# #             "status": "System restored to safe state" if restored else "No rollback needed"
# #         }
# #         return json.dumps(rollback_info, indent=2)
