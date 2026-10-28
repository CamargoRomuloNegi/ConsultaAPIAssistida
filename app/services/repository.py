# -*- coding: utf-8 -*-
"""
Camada de Repositório e Regras de Negócio da Etapa 1:
- Autenticação e Gestão de Usuários (RBAC: ADMIN vs FISCAL)
- Gestão Multi-Cliente (Matriz 8 dígitos e Filiais 14 dígitos)
- Cálculo do Semáforo da Janela Incremental de 8 Dias da Receita Federal
- Cofre Criptografado de Credenciais Receita Integra e Certificados Digitais ICP-Brasil (.pfx)
- Registro Automático de Trilha de Auditoria (Audit Log) com mascaramento de dados sensíveis
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.core.config import DB_PATH, VAULT_CERTS_DIR, RFB_INCREMENTAL_WINDOW_DAYS, RFB_PRIOR_QUERY_LOOKBACK_DAYS
from app.core.database import db_session
from app.core.network_security import mask_sensitive_text
from app.core.security import SecretVault, PasswordHasher, CertificateInspector
from app.models.schemas import (
    ClientCreateInput,
    BranchCreateInput,
    CredentialUpsertInput,
    SyncWindowStatus,
)


def compute_sync_window_semaphore(ultima_consulta_iso: Optional[str]) -> SyncWindowStatus:
    """
    Calcula o Semáforo de Sincronização segundo a regra da seção 3 da documentação de Débitos CBS
    e item 13 do FAQ oficial (https://docs.receitafederal.gov.br/apuracao-cbs/faq.html):
    - Sem consulta nos últimos 90 dias (3 meses): a busca traz desde o 1º dia do mês corrente (AZUL_INICIAL).
    - Com consulta há <= 5 dias: dentro da janela segura de 8 dias (VERDE).
    - Com consulta entre 6 e 7 dias: alerta preventivo para consultar antes que a janela de 8 dias estoure (AMARELO).
    - Com consulta entre 8 e 90 dias: risco de hiato! A API limitará o retorno aos últimos 8 dias (VERMELHO_HIATO).
    """
    if not ultima_consulta_iso:
        return SyncWindowStatus(
            status_code="AZUL_INICIAL",
            badge_label="1ª Consulta do Trimestre (Mês Completo)",
            dias_desde_ultima_consulta=None,
            explicacao_regra_rfb=(
                "Sem consulta concluída nos últimos 3 meses: a próxima requisição trará todos os débitos desde o 1º dia do mês corrente."
            ),
        )

    try:
        dt_last = datetime.fromisoformat(ultima_consulta_iso)
        if dt_last.tzinfo is None:
            dt_last = dt_last.replace(tzinfo=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        days = max(0, (now_utc - dt_last).days)
    except Exception:
        return SyncWindowStatus(
            status_code="AZUL_INICIAL",
            badge_label="Data Inválida",
            dias_desde_ultima_consulta=None,
            explicacao_regra_rfb="Data de última consulta não reconhecida.",
        )

    if days > RFB_PRIOR_QUERY_LOOKBACK_DAYS:
        return SyncWindowStatus(
            status_code="AZUL_INICIAL",
            badge_label=f"Sem consulta há {days} dias (>3 meses)",
            dias_desde_ultima_consulta=days,
            explicacao_regra_rfb="Última consulta ocorreu há mais de 3 meses: a API retornará desde o 1º dia do mês corrente.",
        )
    if days <= 5:
        return SyncWindowStatus(
            status_code="VERDE",
            badge_label=f"Sincronizado ({days}d atrás)",
            dias_desde_ultima_consulta=days,
            explicacao_regra_rfb=f"Dentro da janela incremental segura de {RFB_INCREMENTAL_WINDOW_DAYS} dias da Receita Federal.",
        )
    if days < RFB_INCREMENTAL_WINDOW_DAYS:
        return SyncWindowStatus(
            status_code="AMARELO",
            badge_label=f"Atenção: {days}d sem consulta (Limite: 8d)",
            dias_desde_ultima_consulta=days,
            explicacao_regra_rfb=(
                f"Faltam {RFB_INCREMENTAL_WINDOW_DAYS - days} dia(s) para atingir o limite de 8 dias da API. Execute uma consulta hoje para evitar hiato."
            ),
        )
    return SyncWindowStatus(
        status_code="VERMELHO_HIATO",
        badge_label=f"Risco de Hiato ({days}d sem consulta!)",
        dias_desde_ultima_consulta=days,
        explicacao_regra_rfb=(
            f"A última consulta foi há {days} dias (excede o limite de 8 dias da RFB). A API retornará apenas os últimos 8 dias."
        ),
    )


class OfficeRepository:
    """Repositório central de operações de banco de dados e cofre de segurança do escritório."""

    def __init__(self, db_path: Path = DB_PATH, vault: Optional[SecretVault] = None):
        self.db_path = db_path
        self.vault = vault or SecretVault()

    def log_audit(
        self,
        user_email: str,
        user_role: str,
        action: str,
        target_entity: str,
        details: str,
        ip_address: str = "127.0.0.1",
    ) -> None:
        """Registra evento na trilha de auditoria garantindo mascaramento de qualquer dado sensível."""
        now_iso = datetime.now(timezone.utc).isoformat()
        safe_details = mask_sensitive_text(details)
        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (timestamp_utc, user_email, user_role, action, target_entity, details_masked, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now_iso, user_email, user_role, action, target_entity, safe_details, ip_address),
            )

    def authenticate_user(self, email: str, password: str, ip_address: str = "127.0.0.1") -> Optional[Dict[str, Any]]:
        """Autentica usuário por e-mail e senha e registra o evento no log de auditoria."""
        email_clean = (email or "").strip().lower()
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE lower(email) = ? AND ativo = 1",
                (email_clean,),
            ).fetchone()

        if not row or not PasswordHasher.verify_password(password, row["password_hash"]):
            self.log_audit(
                user_email=email_clean or "desconhecido",
                user_role="ANONIMO",
                action="LOGIN_FALHA",
                target_entity="users",
                details=f"Tentativa de login inválida para {email_clean}",
                ip_address=ip_address,
            )
            return None

        user_dict = dict(row)
        user_dict.pop("password_hash", None)
        self.log_audit(
            user_email=user_dict["email"],
            user_role=user_dict["role"],
            action="LOGIN_SUCESSO",
            target_entity="users",
            details=f"Login autenticado com perfil {user_dict['role']}",
            ip_address=ip_address,
        )
        return user_dict

    def list_users(self) -> List[Dict[str, Any]]:
        with db_session(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, nome, email, role, ativo, created_at FROM users ORDER BY id ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def create_user(
        self,
        nome: str,
        email: str,
        password: str,
        role: str,
        actor_email: str,
        actor_role: str,
    ) -> int:
        if actor_role != "ADMIN":
            raise PermissionError("Apenas usuários com perfil ADMIN podem cadastrar usuários.")
        role_up = role.strip().upper()
        if role_up not in ("ADMIN", "FISCAL"):
            raise ValueError("O perfil deve ser ADMIN ou FISCAL.")
        now_iso = datetime.now(timezone.utc).isoformat()
        with db_session(self.db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO users (nome, email, password_hash, role, ativo, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (nome.strip(), email.strip().lower(), PasswordHasher.hash_password(password), role_up, now_iso),
            )
            uid = cur.lastrowid
        self.log_audit(
            actor_email,
            actor_role,
            "CRIAR_USUARIO",
            f"user:{email.strip().lower()}",
            f"Novo usuário cadastrado com perfil {role_up}",
        )
        return uid

    def list_clients_with_status(self) -> List[Dict[str, Any]]:
        """
        Lista todos os clientes do escritório contábil, incluindo filiais, status de configuração
        de credenciais (sem expor segredos!) e o Semáforo da Janela de 8 Dias da RFB.
        """
        with db_session(self.db_path) as conn:
            clients = conn.execute(
                """
                SELECT c.*,
                       ac.ambiente AS cred_ambiente,
                       ac.oauth_client_id AS cred_client_id,
                       ac.webhook_url_retorno AS cred_webhook,
                       ac.cert_file_name AS cert_file_name,
                       ac.cert_subject_cn AS cert_subject_cn,
                       ac.cert_valid_until AS cert_valid_until,
                       ac.updated_at AS cred_updated_at
                FROM clients c
                LEFT JOIN api_credentials ac ON ac.client_id = c.id
                ORDER BY c.razao_social ASC
                """
            ).fetchall()

            result = []
            for row in clients:
                c_dict = dict(row)
                branches = conn.execute(
                    "SELECT * FROM client_branches WHERE client_id = ? ORDER BY is_matriz DESC, cnpj_completo ASC",
                    (c_dict["id"],),
                ).fetchall()
                c_dict["branches"] = [dict(b) for b in branches]
                c_dict["has_credentials"] = bool(c_dict.get("cred_client_id"))
                c_dict["has_certificate"] = bool(c_dict.get("cert_file_name"))
                c_dict["semaforo"] = compute_sync_window_semaphore(
                    c_dict.get("ultima_consulta_debitos_em")
                ).to_dict()
                result.append(c_dict)
            return result

    def create_client(self, data: ClientCreateInput, actor_email: str, actor_role: str) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        with db_session(self.db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO clients (
                    cnpj_base, cnpj_matriz_completo, razao_social, regime_tributario,
                    responsavel_fiscal, ativo, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    data.cnpj_base,
                    data.cnpj_matriz_completo,
                    data.razao_social.strip(),
                    data.regime_tributario,
                    data.responsavel_fiscal.strip(),
                    now_iso,
                    now_iso,
                ),
            )
            cid = cur.lastrowid
            conn.execute(
                """
                INSERT INTO client_branches (client_id, cnpj_completo, nome_fantasia, uf, municipio, is_matriz, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    cid,
                    data.cnpj_matriz_completo,
                    f"{data.razao_social.strip()[:30]} - Matriz",
                    data.uf_matriz.upper(),
                    data.municipio_matriz.strip(),
                    now_iso,
                ),
            )
        self.log_audit(
            actor_email,
            actor_role,
            "CADASTRAR_CLIENTE",
            f"CNPJ_BASE:{data.cnpj_base}",
            f"Cliente {data.razao_social} (Matriz {data.cnpj_matriz_completo}) cadastrado.",
        )
        return cid

    def add_branch(self, data: BranchCreateInput, actor_email: str, actor_role: str) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        with db_session(self.db_path) as conn:
            client_row = conn.execute(
                "SELECT cnpj_base, razao_social FROM clients WHERE id = ?",
                (data.client_id,),
            ).fetchone()
            if not client_row:
                raise ValueError("Cliente matriz não encontrado.")
            if not data.cnpj_completo.startswith(client_row["cnpj_base"]):
                raise ValueError(
                    f"O CNPJ da filial ({data.cnpj_completo}) não pertence à raiz de 8 dígitos da matriz ({client_row['cnpj_base']})."
                )
            cur = conn.execute(
                """
                INSERT INTO client_branches (client_id, cnpj_completo, nome_fantasia, uf, municipio, is_matriz, created_at)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    data.client_id,
                    data.cnpj_completo,
                    data.nome_fantasia.strip(),
                    data.uf.upper(),
                    data.municipio.strip(),
                    now_iso,
                ),
            )
            bid = cur.lastrowid
        self.log_audit(
            actor_email,
            actor_role,
            "CADASTRAR_FILIAL",
            f"FILIAL:{data.cnpj_completo}",
            f"Filial {data.nome_fantasia} vinculada à raiz {client_row['cnpj_base']}",
        )
        return bid

    def upsert_api_credentials(
        self,
        data: CredentialUpsertInput,
        actor_email: str,
        actor_role: str,
        pfx_bytes: Optional[bytes] = None,
        pfx_filename: str = "",
        pfx_password: str = "",
    ) -> Dict[str, Any]:
        """
        Salva ou rotaciona as credenciais OAuth2 do Receita Integra e opcionalmente o
        certificado digital ICP-Brasil (.pfx) para o cliente selecionado.
        Operação estritamente bloqueada para usuários que não sejam ADMIN.
        """
        if actor_role != "ADMIN":
            self.log_audit(
                actor_email,
                actor_role,
                "ACESSO_NEGADO_COFRE",
                f"client_id:{data.client_id}",
                "Tentativa bloqueada de alteração de credenciais por perfil não-ADMIN.",
            )
            raise PermissionError("Acesso negado: apenas o perfil ADMIN pode gerenciar credenciais e certificados.")

        now_iso = datetime.now(timezone.utc).isoformat()
        secret_enc = self.vault.encrypt(data.oauth_client_secret)

        cert_info = None
        saved_cert_name = ""
        cert_pwd_enc = ""
        cert_subject = ""
        cert_valid_until = ""

        if pfx_bytes:
            cert_info = CertificateInspector.inspect_pfx_bytes(pfx_bytes, pfx_password)
            safe_name = f"client_{data.client_id}_{Path(pfx_filename or 'cert.pfx').name}"
            cert_path = VAULT_CERTS_DIR / safe_name
            cert_path.write_bytes(pfx_bytes)
            try:
                cert_path.chmod(0o600)
            except OSError:
                pass
            saved_cert_name = safe_name
            cert_pwd_enc = self.vault.encrypt(pfx_password)
            cert_subject = cert_info["subject_cn"]
            cert_valid_until = cert_info["valid_until_iso"]

        with db_session(self.db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM api_credentials WHERE client_id = ?",
                (data.client_id,),
            ).fetchone()

            if existing:
                final_cert_name = saved_cert_name or existing["cert_file_name"]
                final_cert_pwd = cert_pwd_enc or existing["cert_password_enc"]
                final_cert_subj = cert_subject or existing["cert_subject_cn"]
                final_cert_valid = cert_valid_until or existing["cert_valid_until"]

                conn.execute(
                    """
                    UPDATE api_credentials
                    SET ambiente = ?,
                        oauth_client_id = ?,
                        oauth_client_secret_enc = ?,
                        webhook_url_retorno = ?,
                        cert_file_name = ?,
                        cert_password_enc = ?,
                        cert_subject_cn = ?,
                        cert_valid_until = ?,
                        updated_by_email = ?,
                        updated_at = ?
                    WHERE client_id = ?
                    """,
                    (
                        data.ambiente,
                        data.oauth_client_id.strip(),
                        secret_enc,
                        data.webhook_url_retorno,
                        final_cert_name,
                        final_cert_pwd,
                        final_cert_subj,
                        final_cert_valid,
                        actor_email,
                        now_iso,
                        data.client_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO api_credentials (
                        client_id, ambiente, oauth_client_id, oauth_client_secret_enc,
                        webhook_url_retorno, cert_file_name, cert_password_enc,
                        cert_subject_cn, cert_valid_until, updated_by_email, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data.client_id,
                        data.ambiente,
                        data.oauth_client_id.strip(),
                        secret_enc,
                        data.webhook_url_retorno,
                        saved_cert_name,
                        cert_pwd_enc,
                        cert_subject,
                        cert_valid_until,
                        actor_email,
                        now_iso,
                    ),
                )

        self.log_audit(
            actor_email,
            actor_role,
            "ATUALIZAR_CREDENCIAIS_COFRE",
            f"client_id:{data.client_id}",
            f"Credencial OAuth2 ({data.oauth_client_id}) atualizada no ambiente {data.ambiente}. Certificado: {saved_cert_name or 'mantido'}.",
        )
        return {"status": "ok", "cert_info": cert_info}

    def get_decrypted_credentials_for_backend(
        self, client_id: int, actor_email: str, actor_role: str
    ) -> Dict[str, Any]:
        """
        Uso exclusivo do conector interno da API (Etapa 2): descriptografa `client_secret`
        em memória para autenticar no Receita Integra. Jamais exposto diretamente na UI.
        """
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM api_credentials WHERE client_id = ?",
                (client_id,),
            ).fetchone()
            if not row:
                raise ValueError("Cliente não possui credenciais configuradas no cofre.")
            d = dict(row)
            d["oauth_client_secret_plain"] = self.vault.decrypt(d["oauth_client_secret_enc"])
            return d

    def list_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with db_session(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
