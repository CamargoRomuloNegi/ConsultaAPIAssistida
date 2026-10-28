# -*- coding: utf-8 -*-
"""
Módulo de Criptografia em Repouso (Cofre de Credenciais), Inspeção de Certificados ICP-Brasil
e Controle de Acesso Baseado em Papéis (RBAC: ADMIN vs FISCAL).

Decisões de Engenharia de Segurança:
1. Criptografia Simétrica Autenticada (Fernet: AES-128-CBC + HMAC-SHA256) para proteger o
   `client_secret` do Receita Integra e a senha de certificados digitais `.pfx`/`.p12`.
2. Senhas de usuários armazenadas exclusivamente como hashes `PBKDF2-HMAC-SHA256` (390.000 iterações)
   com salt criptográfico único por usuário.
3. Inspeção de Certificados Digitais A1 (`.pfx`/`.p12`) usando a biblioteca `cryptography`,
   extraindo titular, emissor, validade e CNPJ sem expor a chave privada.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

from app.core.config import MASTER_KEY_PATH, SESSION_TTL_SECONDS


class SecretVault:
    """
    Cofre criptográfico local responsável por cifrar e decifrar segredos de API
    (`client_secret` e senhas de certificados `.pfx`) em repouso no banco SQLite.
    """

    def __init__(self, key_path=MASTER_KEY_PATH):
        self.key_path = key_path
        self._fernet = Fernet(self._load_or_create_master_key())

    def _load_or_create_master_key(self) -> bytes:
        env_key = os.environ.get("CBS_MASTER_KEY")
        if env_key:
            # Deriva chave Fernet de 32 bytes url-safe a partir da variável de ambiente
            digest = hashlib.sha256(env_key.encode("utf-8")).digest()
            return base64.urlsafe_b64encode(digest)

        if self.key_path.exists():
            return self.key_path.read_bytes().strip()

        key = Fernet.generate_key()
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(key)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return key

    def encrypt(self, plaintext: str) -> str:
        """Criptografa uma string sensível retornando o token Fernet em UTF-8."""
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Descriptografa um token Fernet retornando a string original em memória."""
        if not ciphertext:
            return ""
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Falha ao descriptografar segredo do cofre: chave mestra inválida ou dado corrompido.") from exc


class PasswordHasher:
    """Gerenciador de hashes seguros PBKDF2-HMAC-SHA256 para senhas de usuários do escritório."""

    ITERATIONS = 390_000

    @classmethod
    def hash_password(cls, password: str) -> str:
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            cls.ITERATIONS,
        )
        return f"pbkdf2_sha256${cls.ITERATIONS}${salt}${dk.hex()}"

    @classmethod
    def verify_password(cls, password: str, stored_hash: str) -> bool:
        try:
            algo, iter_str, salt, hex_digest = stored_hash.split("$")
            if algo != "pbkdf2_sha256":
                return False
            iterations = int(iter_str)
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            )
            return hmac.compare_digest(dk.hex(), hex_digest)
        except Exception:
            return False


class SessionManager:
    """Gerencia tokens de sessão assinados com HMAC-SHA256 para autenticação na interface Web."""

    def __init__(self, vault: Optional[SecretVault] = None):
        self.vault = vault or SecretVault()
        self._signing_key = self.vault._load_or_create_master_key()

    def create_session_token(self, user_id: int, email: str, role: str, nome: str) -> str:
        payload = {
            "sub": user_id,
            "email": email,
            "role": role.upper(),
            "nome": nome,
            "exp": int(time.time()) + SESSION_TTL_SECONDS,
            "nonce": secrets.token_hex(8),
        }
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("utf-8")
        sig = hmac.new(
            self._signing_key, payload_b64.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"{payload_b64}.{sig}"

    def verify_session_token(self, token: str) -> Optional[Dict[str, Any]]:
        if not token or "." not in token:
            return None
        try:
            payload_b64, sig = token.split(".", 1)
            expected_sig = hmac.new(
                self._signing_key, payload_b64.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return None
            payload = json.loads(
                base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
            )
            if int(time.time()) > int(payload.get("exp", 0)):
                return None
            return payload
        except Exception:
            return None


class CertificateInspector:
    """
    Utilitário para validar e inspecionar Certificados Digitais ICP-Brasil (A1 .pfx / .p12)
    no momento do upload pelo Administrador, garantindo que a senha está correta e
    extraindo metadados de auditoria (Titular, CNPJ, Emissor e Data de Vencimento).
    """

    @staticmethod
    def inspect_pfx_bytes(pfx_bytes: bytes, password: str) -> Dict[str, Any]:
        try:
            pwd_bytes = password.encode("utf-8") if password else None
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                pfx_bytes, pwd_bytes
            )
        except Exception as exc:
            raise ValueError(
                f"Não foi possível abrir o certificado digital (.pfx/.p12). Verifique o arquivo e a senha informada. Detalhe: {exc}"
            ) from exc

        if cert is None:
            raise ValueError("O arquivo PKCS#12 informado não contém um certificado X.509 válido.")

        if private_key is None:
            raise ValueError("O arquivo PKCS#12 não contém chave privada correspondente (necessária para mTLS).")

        subject_cn = ""
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                subject_cn = str(attr.value)
                break

        issuer_cn = ""
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = str(attr.value)
                break

        # Em certificados e-CNPJ ICP-Brasil, o Common Name costuma seguir o padrão "RAZAO SOCIAL:12345678000199"
        extracted_cnpj = ""
        if ":" in subject_cn:
            candidate = "".join(ch for ch in subject_cn.split(":")[-1] if ch.isdigit())
            if len(candidate) == 14:
                extracted_cnpj = candidate

        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        days_remaining = (not_after - now_utc).days

        return {
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "serial_number": format(cert.serial_number, "X"),
            "extracted_cnpj": extracted_cnpj,
            "valid_from_iso": not_before.isoformat(),
            "valid_until_iso": not_after.isoformat(),
            "days_remaining": days_remaining,
            "is_expired": days_remaining < 0,
            "chain_length": 1 + (len(additional_certs) if additional_certs else 0),
        }
