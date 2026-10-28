# -*- coding: utf-8 -*-
"""
Suíte de Testes Automatizados e Auditáveis da Etapa 1:
Valida Banco SQLite WAL, Cofre Fernet, Inspeção de Certificado ICP-Brasil (.pfx),
Controle de Acesso Segregado (RBAC ADMIN vs FISCAL), Semáforo de 8 Dias e Blindagem de Rede/Webhook.
"""

import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.core.database import init_db, get_connection
from app.core.network_security import (
    mask_sensitive_text,
    validate_rfb_webhook_ip,
    run_network_and_security_diagnostics,
)
from app.core.security import SecretVault, PasswordHasher, CertificateInspector
from app.models.schemas import ClientCreateInput, CredentialUpsertInput
from app.services.repository import OfficeRepository, compute_sync_window_semaphore
from app.web.main import app


def generate_self_signed_pfx(cn: str = "EMPRESA TESTE LTDA:00409834000188", password: str = "SenhaCert123") -> bytes:
    """Gera um arquivo .pfx (PKCS#12) válido em memória para testar o inspetor de certificados A1."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ICP-Brasil Teste"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return pkcs12.serialize_key_and_certificates(
        name=b"cert-e-cnpj",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


class TestEtapa1FundacaoSeguranca(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_cbs.db"
        self.key_path = Path(self.tmp_dir.name) / ".test_master.key"
        self.vault = SecretVault(key_path=self.key_path)
        init_db(db_path=self.db_path, seed_demo=True)
        self.repo = OfficeRepository(db_path=self.db_path, vault=self.vault)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_01_sqlite_wal_mode_enabled(self):
        conn = get_connection(self.db_path)
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        conn.close()
        self.assertEqual(mode.lower(), "wal")

    def test_02_secret_vault_encryption_roundtrip(self):
        raw_secret = "meu-client-secret-receita-integra-2026"
        encrypted = self.vault.encrypt(raw_secret)
        self.assertNotEqual(raw_secret, encrypted)
        self.assertEqual(self.vault.decrypt(encrypted), raw_secret)

    def test_03_certificate_inspector_extracts_cnpj_and_validity(self):
        pfx_bytes = generate_self_signed_pfx("METALURGICA ALFA SA:00409834000188", "Cert@2026")
        info = CertificateInspector.inspect_pfx_bytes(pfx_bytes, "Cert@2026")
        self.assertEqual(info["extracted_cnpj"], "00409834000188")
        self.assertFalse(info["is_expired"])
        self.assertGreater(info["days_remaining"], 300)

        with self.assertRaises(ValueError):
            CertificateInspector.inspect_pfx_bytes(pfx_bytes, "SenhaErrada")

    def test_04_rbac_blocks_fiscal_from_updating_credentials(self):
        clients = self.repo.list_clients_with_status()
        target_client_id = clients[0]["id"]
        cred_input = CredentialUpsertInput(
            client_id=target_client_id,
            ambiente="PRODUCAO",
            oauth_client_id="novo-client-id",
            oauth_client_secret="novo-segredo",
            webhook_url_retorno="",
        )
        with self.assertRaises(PermissionError):
            self.repo.upsert_api_credentials(
                data=cred_input,
                actor_email="fiscal@escritorio.cnt.br",
                actor_role="FISCAL",
            )

        # Já o perfil ADMIN consegue gravar e anexar certificado .pfx com sucesso
        pfx_bytes = generate_self_signed_pfx()
        res = self.repo.upsert_api_credentials(
            data=cred_input,
            actor_email="admin@escritorio.cnt.br",
            actor_role="ADMIN",
            pfx_bytes=pfx_bytes,
            pfx_filename="alfa.pfx",
            pfx_password="SenhaCert123",
        )
        self.assertEqual(res["status"], "ok")
        dec = self.repo.get_decrypted_credentials_for_backend(
            target_client_id, "admin@escritorio.cnt.br", "ADMIN"
        )
        self.assertEqual(dec["oauth_client_secret_plain"], "novo-segredo")

    def test_05_network_security_and_log_masking(self):
        raw = (
            "Authorization: Bearer token_secreto_123 "
            "URL: https://storage.gov.br/ret.json?X-Amz-Signature=99887766 "
            "client_secret=segredo_abc"
        )
        masked = mask_sensitive_text(raw)
        self.assertNotIn("token_secreto_123", masked)
        self.assertNotIn("99887766", masked)
        self.assertNotIn("segredo_abc", masked)

        self.assertTrue(validate_rfb_webhook_ip("189.9.61.23", "PRODUCAO"))
        self.assertFalse(validate_rfb_webhook_ip("200.160.2.3", "PRODUCAO"))

    def test_06_sync_window_semaphore_8_days_rule(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        s_verde = compute_sync_window_semaphore((now - datetime.timedelta(days=3)).isoformat())
        s_amarelo = compute_sync_window_semaphore((now - datetime.timedelta(days=7)).isoformat())
        s_vermelho = compute_sync_window_semaphore((now - datetime.timedelta(days=12)).isoformat())
        s_azul = compute_sync_window_semaphore(None)

        self.assertEqual(s_verde.status_code, "VERDE")
        self.assertEqual(s_amarelo.status_code, "AMARELO")
        self.assertEqual(s_vermelho.status_code, "VERMELHO_HIATO")
        self.assertEqual(s_azul.status_code, "AZUL_INICIAL")

    def test_07_web_interface_and_rbac_http_routes(self):
        with TestClient(app) as client:
        # Login page carrega
            r_login = client.get("/login")
            self.assertEqual(r_login.status_code, 200)

        # Autentica como FISCAL
            r_auth_fiscal = client.post(
                    "/login",
                data={"email": "fiscal@escritorio.cnt.br", "password": "Fiscal@2026!"},
                follow_redirects=True,
            )
            self.assertEqual(r_auth_fiscal.status_code, 200)
            self.assertIn("PERFIL: FISCAL", r_auth_fiscal.text)

        # Tenta chamar endpoint /admin/credenciais como FISCAL -> Deve receber 403 Forbidden
            r_forbid = client.post(
                    "/admin/credenciais",
                data={
                    "client_id": 1,
                    "ambiente": "PRODUCAO",
                    "oauth_client_id": "x",
                    "oauth_client_secret": "y",
                    "webhook_url_retorno": "",
                },
            )
            self.assertEqual(r_forbid.status_code, 403)

        # Testa endpoint HEAD do Webhook da RFB
            r_head = client.head("/webhooks/rfb/apuracao-cbs")
            self.assertEqual(r_head.status_code, 200)


if __name__ == "__main__":
    unittest.main()
