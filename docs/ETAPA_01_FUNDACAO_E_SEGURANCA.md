# Documentação Técnica — Etapa 1: Fundação, Banco de Dados Local (SQLite WAL), Segurança e RBAC

**Projeto:** Auditoria e Confronto da Apuração Assistida (CBS / IBS)  
**Arquiteto Técnico:** Titular do Projeto (Usuário)  
**Orquestrador Técnico e Engenharia:** Gemini (Google AI)  
**Versão:** 1.0.0 — Etapa 1 Concluída e Testada em 28/10/2026

## 1. Escopo Entregue na Etapa 1

1. **Banco de Dados Local SQLite 3 em Modo WAL (`app/core/database.py`):**
   * Configuração transacional ACID com `PRAGMA journal_mode=WAL;`, `PRAGMA synchronous=NORMAL;` e `PRAGMA foreign_keys=ON;`.
   * Tabelas implementadas com DDL explícito: `users`, `clients`, `client_branches`, `api_credentials`, `api_quota_ledger` e `audit_logs`.
2. **Modelagem Multi-Cliente (Matriz 8 dígitos vs. Filiais 14 dígitos):**
   * Cada cliente é indexado pelo `cnpj_base` (8 dígitos exigidos pela rota `/apuracao-cbs/v2/debitos/{cnpj}`), permitindo vincular múltiplos estabelecimentos/filiais de 14 dígitos (`client_branches`) para conciliação consolidada ou por filial.
3. **Semáforo da Janela Incremental de 8 Dias (`compute_sync_window_semaphore`):**
   * Calcula automaticamente em qual situação da regra da Receita Federal cada cliente se encontra (`VERDE` $\le 5$ dias, `AMARELO` $6\text{–}7$ dias, `VERMELHO_HIATO` $\ge 8$ dias, ou `AZUL_INICIAL` quando não há consulta nos últimos 90 dias).
4. **Segurança Criptográfica, Certificados ICP-Brasil e Rede (`app/core/security.py` e `app/core/network_security.py`):**
   * Cofre `SecretVault` (Fernet AES-128-CBC + HMAC-SHA256) protegendo `oauth_client_secret_enc` e `cert_password_enc`.
   * Inspetor `CertificateInspector` para validação de certificados `.pfx`/`.p12` ICP-Brasil.
   * Filtro `SensitiveDataLogFilter` para mascaramento automático de tokens `Bearer` e `urlAssinada` S3.
   * Validação de IP de origem do Webhook da RFB (`189.9.61.23/32`).
5. **Interface Web e Controle de Acesso Segregado (`app/web/main.py`):**
   * Autenticação por sessão assinada via HMAC-SHA256 (`HttpOnly`).
   * Painel segregado entre `ADMIN` (acesso completo ao Cofre de Credenciais/Certificados e Gestão de Usuários) e `FISCAL` (operação fiscal sem exposição de segredos).

## 2. Resultados da Suíte de Testes Automatizados (`tests/test_etapa1.py`)

* `test_01_sqlite_wal_mode_enabled` — Verifica ativação do modo WAL no SQLite.
* `test_02_secret_vault_encryption_roundtrip` — Valida criptografia e descriptografia Fernet de `client_secret`.
* `test_03_certificate_inspector_extracts_cnpj_and_validity` — Gera certificado ICP-Brasil `.pfx` em memória e valida extração de CNPJ, validade e rejeição de senha incorreta.
* `test_04_rbac_blocks_fiscal_from_updating_credentials` — Comprova que o perfil `FISCAL` recebe `PermissionError` ao tentar manipular credenciais, enquanto `ADMIN` grava e criptografa com sucesso.
* `test_05_network_security_and_log_masking` — Comprova mascaramento de `Bearer`, `X-Amz-Signature` (`urlAssinada`) e `client_secret`, além do filtro CIDR `189.9.61.23/32`.
* `test_06_sync_window_semaphore_8_days_rule` — Valida os 4 estados do Semáforo da Janela de 8 Dias.
* `test_07_web_interface_and_rbac_http_routes` — Testa login web, renderização do painel, bloqueio `HTTP 403` na rota `/admin/credenciais` para perfil `FISCAL` e resposta `HTTP 200` no `HEAD /webhooks/rfb/apuracao-cbs`.
