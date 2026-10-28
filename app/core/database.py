# -*- coding: utf-8 -*-
"""
Gerenciador de Banco de Dados Local SQLite 3 configurado com Modo WAL (Write-Ahead Logging)
e fallback resiliente automático para sistemas de arquivos em rede/virtualizados (SMB/NFS/FUSE).

Por que SQLite 3 (WAL + Fallback Resiliente) + SQL Explícito?
1. Zero custo de servidor para o escritório contábil (arquivo único `data/apuracao_cbs.db`).
2. `PRAGMA journal_mode=WAL` habilita leituras e escritas concorrentes em discos locais, e o
   fallback automático para `DELETE` evita erros de `disk I/O` caso o escritório execute a pasta
   em um diretório de rede mapeado ou container virtualizado que não suporte `mmap` (`-shm`).
3. Todas as tabelas possuem DDL SQL explícito e documentado, facilitando auditoria e futura
   migração para PostgreSQL, SQL Server ou outra linguagem (C#, Java, Node.js).
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from app.core.config import DB_PATH
from app.core.security import PasswordHasher, SecretVault


SCHEMA_DDL = """
-- 1. Tabela de Usuários do Escritório Contábil (Controle de Acesso Segregado - RBAC)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ADMIN', 'FISCAL')),
    ativo INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

-- 2. Tabela de Clientes do Escritório (Agrupados pela Raiz do CNPJ Básico de 8 dígitos - Matriz)
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cnpj_base TEXT NOT NULL UNIQUE CHECK (length(cnpj_base) = 8),
    cnpj_matriz_completo TEXT NOT NULL CHECK (length(cnpj_matriz_completo) = 14),
    razao_social TEXT NOT NULL,
    regime_tributario TEXT NOT NULL DEFAULT 'REGIME_REGULAR',
    responsavel_fiscal TEXT DEFAULT '',
    ultima_consulta_debitos_em TEXT DEFAULT NULL,
    ultimo_tiquete_debitos TEXT DEFAULT NULL,
    ativo INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 3. Tabela de Estabelecimentos / Filiais (14 dígitos) vinculados ao CNPJ Base (8 dígitos)
CREATE TABLE IF NOT EXISTS client_branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    cnpj_completo TEXT NOT NULL UNIQUE CHECK (length(cnpj_completo) = 14),
    nome_fantasia TEXT NOT NULL,
    uf TEXT NOT NULL CHECK (length(uf) = 2),
    municipio TEXT NOT NULL,
    is_matriz INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- 4. Cofre de Credenciais da API Receita Integra e Certificados Digitais ICP-Brasil (Acesso exclusivo ADMIN)
CREATE TABLE IF NOT EXISTS api_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL UNIQUE,
    ambiente TEXT NOT NULL DEFAULT 'PRODUCAO' CHECK (ambiente IN ('PRODUCAO', 'PRR')),
    oauth_client_id TEXT NOT NULL,
    oauth_client_secret_enc TEXT NOT NULL,
    webhook_url_retorno TEXT NOT NULL DEFAULT '',
    cert_file_name TEXT DEFAULT '',
    cert_password_enc TEXT DEFAULT '',
    cert_subject_cn TEXT DEFAULT '',
    cert_valid_until TEXT DEFAULT '',
    cached_access_token_enc TEXT DEFAULT '',
    token_expires_at TEXT DEFAULT NULL,
    tokens_issued_current_hour INTEGER NOT NULL DEFAULT 0,
    token_hour_window_start TEXT DEFAULT NULL,
    updated_by_email TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- 5. Controle de Cota Diária (Limite de 4 chamadas/dia por credencial e por API da RFB)
CREATE TABLE IF NOT EXISTS api_quota_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    api_tipo TEXT NOT NULL CHECK (api_tipo IN ('DEBITOS', 'CREDITOS', 'PAGAMENTOS', 'RECOLHIMENTOS')),
    data_referencia TEXT NOT NULL, -- YYYY-MM-DD
    chamadas_realizadas INTEGER NOT NULL DEFAULT 0,
    ultimo_tiquete TEXT DEFAULT '',
    updated_at TEXT NOT NULL,
    UNIQUE(client_id, api_tipo, data_referencia),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- 6. Trilha de Auditoria Imutável (Audit Log de Segurança e Operações Fiscais)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    details_masked TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '127.0.0.1'
);
"""


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """
    Abre conexão SQLite 3 configurada com WAL em disco local e fallback automático
    para `DELETE` caso o diretório esteja montado em rede/container sem suporte a `mmap`.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        # Verifica se uma operação real funciona no modo WAL neste filesystem
        conn.execute("SELECT count(*) FROM sqlite_master;").fetchone()
        conn.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.OperationalError:
        conn.close()
        # Remove artefatos -wal/-shm caso o filesystem de rede tenha falhado no mmap
        for suffix in ("-wal", "-shm"):
            p = Path(str(db_path) + suffix)
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass
        conn = sqlite3.connect(str(db_path), timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=DELETE;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
    return conn


@contextmanager
def db_session(db_path: Path = DB_PATH) -> Iterator[sqlite3.Connection]:
    """Context manager transacional com commit automático em sucesso e rollback em exceção."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path = DB_PATH, seed_demo: bool = True) -> None:
    """
    Cria todas as tabelas do esquema e, se o banco estiver vazio, popula os dois perfis
    padrão (ADMIN e FISCAL) e três clientes demonstrativos para o escritório contábil.
    """
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()
    vault = SecretVault()

    with db_session(db_path) as conn:
        conn.executescript(SCHEMA_DDL)

        if not seed_demo:
            return

        cur = conn.execute("SELECT COUNT(*) AS cnt FROM users")
        if cur.fetchone()["cnt"] == 0:
            conn.execute(
                """
                INSERT INTO users (nome, email, password_hash, role, ativo, created_at)
                VALUES (?, ?, ?, 'ADMIN', 1, ?),
                       (?, ?, ?, 'FISCAL', 1, ?)
                """,
                (
                    "Arquiteto Técnico (Administrador Geral)",
                    "admin@escritorio.cnt.br",
                    PasswordHasher.hash_password("Admin@2026!"),
                    now_iso,
                    "Analista Fiscal Sênior (Auditoria CBS/IBS)",
                    "fiscal@escritorio.cnt.br",
                    PasswordHasher.hash_password("Fiscal@2026!"),
                    now_iso,
                ),
            )

        cur_clients = conn.execute("SELECT COUNT(*) AS cnt FROM clients")
        if cur_clients.fetchone()["cnt"] == 0:
            dt_verde = (now_utc - timedelta(days=2)).isoformat()
            dt_amarelo = (now_utc - timedelta(days=7)).isoformat()

            clientes_seed = [
                (
                    "00409834",
                    "00409834000188",
                    "INDÚSTRIA METALÚRGICA ALFA S.A.",
                    "REGIME_REGULAR",
                    "fiscal@escritorio.cnt.br",
                    dt_verde,
                    "48d88a3c-eff9-4489-8e3a-cde8d878d3f7.1E0CE7A4",
                ),
                (
                    "12345678",
                    "12345678000195",
                    "COMÉRCIO E DISTRIBUIDORA BETA LTDA",
                    "REGIME_REGULAR",
                    "fiscal@escritorio.cnt.br",
                    dt_amarelo,
                    "692b7b25-44cb-4415-8625-2b9522dd7933.B5E08D55",
                ),
                (
                    "98765432",
                    "98765432000123",
                    "LOGÍSTICA E TRANSPORTES GAMA S.A.",
                    "REGIME_REGULAR",
                    "fiscal@escritorio.cnt.br",
                    None,
                    None,
                ),
            ]

            for cnpj_base, cnpj_mat, razao, regime, resp, ult_dt, ult_tiq in clientes_seed:
                cursor = conn.execute(
                    """
                    INSERT INTO clients (
                        cnpj_base, cnpj_matriz_completo, razao_social, regime_tributario,
                        responsavel_fiscal, ultima_consulta_debitos_em, ultimo_tiquete_debitos,
                        ativo, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (cnpj_base, cnpj_mat, razao, regime, resp, ult_dt, ult_tiq, now_iso, now_iso),
                )
                cid = cursor.lastrowid

                conn.execute(
                    """
                    INSERT INTO client_branches (client_id, cnpj_completo, nome_fantasia, uf, municipio, is_matriz, created_at)
                    VALUES (?, ?, ?, 'SP', 'São Paulo', 1, ?)
                    """,
                    (cid, cnpj_mat, f"{razao[:20]} - Matriz SP", now_iso),
                )
                if cnpj_base == "00409834":
                    conn.execute(
                        """
                        INSERT INTO client_branches (client_id, cnpj_completo, nome_fantasia, uf, municipio, is_matriz, created_at)
                        VALUES (?, '00409834000269', 'ALFA FILIAL CAMPINAS', 'SP', 'Campinas', 0, ?)
                        """,
                        (cid, now_iso),
                    )
                    conn.execute(
                        """
                        INSERT INTO api_credentials (
                            client_id, ambiente, oauth_client_id, oauth_client_secret_enc,
                            webhook_url_retorno, cert_file_name, cert_subject_cn, cert_valid_until,
                            updated_by_email, updated_at
                        ) VALUES (?, 'PRODUCAO', ?, ?, '', 'cert_alfa_a1.pfx',
                                  'INDUSTRIA METALURGICA ALFA SA:00409834000188',
                                  ?, 'admin@escritorio.cnt.br', ?)
                        """,
                        (
                            cid,
                            "integra-client-00409834",
                            vault.encrypt("segredo-oauth2-receita-integra-alfa-2026"),
                            (now_utc + timedelta(days=240)).isoformat(),
                            now_iso,
                        ),
                    )

            conn.execute(
                """
                INSERT INTO audit_logs (timestamp_utc, user_email, user_role, action, target_entity, details_masked, ip_address)
                VALUES (?, 'sistema@escritorio.cnt.br', 'ADMIN', 'INIT_DATABASE', 'SQLite WAL',
                        'Estrutura inicial da Etapa 1 criada com sucesso (RBAC e Cofre Fernet ativos).', '127.0.0.1')
                """,
                (now_iso,),
            )
