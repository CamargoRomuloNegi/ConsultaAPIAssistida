# -*- coding: utf-8 -*-
"""
Configurações globais e constantes oficiais da API de Apuração Assistida da CBS (Receita Federal).

Todas as regras parametrizadas neste módulo refletem fielmente a documentação oficial:
- Portal da Apuração CBS: https://docs.receitafederal.gov.br/apuracao-cbs/
- Guia Comum de APIs Assíncronas (v1.1 de 14/10/2026)
- Manual Técnico Receita Integra (v1.4 de 17/07/2026)
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = Path(os.environ.get("CBS_DATA_DIR", str(BASE_DIR / "data")))
VAULT_CERTS_DIR = DATA_DIR / "vault_certs"
DB_PATH = Path(os.environ.get("CBS_DB_PATH", str(DATA_DIR / "apuracao_cbs.db")))
MASTER_KEY_PATH = Path(os.environ.get("CBS_MASTER_KEY_PATH", str(DATA_DIR / ".master.key")))

# Garante existência dos diretórios de dados e cofre de certificados
DATA_DIR.mkdir(parents=True, exist_ok=True)
VAULT_CERTS_DIR.mkdir(parents=True, exist_ok=True)

# URLs Oficiais da Receita Federal (Receita Integra & Apuração CBS v2)
RFB_OAUTH2_TOKEN_URL = "https://api.receitafederal.gov.br/token"
RFB_BASE_URL_PRODUCAO = "https://api.receitafederal.gov.br/apuracao-cbs/v2"
RFB_BASE_URL_PRR = "https://api.receitafederal.gov.br/apuracao-cbs-prr/v2"

# Limites Operacionais Oficiais da Receita Federal
RFB_MAX_TOKENS_PER_HOUR = 2
RFB_TOKEN_TTL_SECONDS = 3600
RFB_MAX_DAILY_CALLS_PER_API = 4
RFB_MAX_PROCESSING_MINUTES = 240
RFB_SIGNED_URL_TTL_HOURS = 48
RFB_INCREMENTAL_WINDOW_DAYS = 8
RFB_PRIOR_QUERY_LOOKBACK_DAYS = 90

# Faixas de IP autorizadas pela Receita Federal para envio de notificações via Webhook
# Fonte: https://docs.receitafederal.gov.br/apuracao-cbs/guiaapiassincrona.html (Seção 5.2)
RFB_WEBHOOK_ALLOWED_CIDRS_PRODUCAO = ["189.9.61.23/32"]
RFB_WEBHOOK_ALLOWED_CIDRS_PRR = ["189.9.61.23/32", "127.0.0.1/32"]

# Configuração de Sessão Web
SESSION_COOKIE_NAME = "cbs_session_token"
SESSION_TTL_SECONDS = 8 * 3600  # 8 horas (jornada de trabalho no escritório contábil)
