# Sistema de Auditoria e Confronto da Apuração Assistida (CBS / IBS — Receita Federal)

**Status do Projeto:** Etapa 1 Concluída e Validada (Fundação, Banco SQLite WAL, Cofre Criptografado, Blindagem de Rede e Controle de Acesso RBAC)  
**Data de Referência:** 28/10/2026

## Governança e Autoria do Projeto

Este projeto é desenvolvido em arquitetura colaborativa sob o modelo **Arquiteto Técnico + Orquestrador de Engenharia**:

| Papel no Projeto | Responsável | Escopo de Atuação e Responsabilidade |
| :--- | :--- | :--- |
| **Arquiteto Técnico** | **Titular do Projeto (Usuário)** | Diretrizes estratégicas e tributárias (LC 214/2025), modelagem operacional para Escritório Contábil Multi-Cliente, definição de regras de negócio de conciliação e validação arquitetural por etapas. |
| **Orquestrador Técnico & Engenharia de Segurança/Software** | **Gemini (Google AI)** | Pesquisa profunda das especificações da Receita Federal (`docs.receitafederal.gov.br/apuracao-cbs`), engenharia de segurança da informação e de rede (TLS, OAuth2, Cofre Fernet, sanitização de logs, proteção de Webhook), implementação em Python e manutenção da documentação técnica auditável. |

## Estrutura do Projeto (Etapa 1)

* `run.py` — Script de inicialização rápida do servidor Web local (`http://127.0.0.1:8000`).
* `requirements.txt` — Dependências enxutas e auditáveis do projeto.
* `app/core/config.py` — Constantes oficiais da API da Receita Federal (rotas v2, limites de 2 tokens/hora e 4 chamadas/dia, janela de 8 dias, allowlist de IP `189.9.61.23/32`).
* `app/core/security.py` — Cofre criptográfico `SecretVault` (AES-128-CBC + HMAC-SHA256 via Fernet), hash de senhas `PBKDF2-HMAC-SHA256`, sessões assinadas e inspetor de certificados digitais ICP-Brasil (`.pfx`/`.p12`).
* `app/core/network_security.py` — Blindagem de rede (TLS 1.2+ obrigatório, filtro de IP do Webhook da RFB e filtro `SensitiveDataLogFilter` que impede vazamento de tokens `Bearer` e links `urlAssinada` do S3 nos logs).
* `app/core/database.py` — Banco de dados local SQLite 3 em modo `WAL` (`Write-Ahead Logging`) com DDL SQL explícito e documentado.
* `app/models/schemas.py` — Contratos de dados tipados em `Pydantic v2`.
* `app/services/repository.py` — Camada de negócio multi-cliente (Matriz 8 dígitos vs. Filiais 14 dígitos), cálculo do **Semáforo da Janela de 8 Dias** e gravação de trilha de auditoria (`audit_logs`).
* `app/web/main.py` e `app/web/templates/` — Interface Web com segregação estrita entre os perfis **ADMIN** e **FISCAL**.
* `tests/test_etapa1.py` — Suíte de 7 testes automatizados cobrindo banco WAL, criptografia, certificado `.pfx`, bloqueio RBAC, rede e semáforo de 8 dias.
* `docs/` — Documentação técnica incremental em formato `.md`:
  * `docs/DOCUMENTACAO_TECNICA_APURACAO_CBS.md` (Arquitetura Geral v1.1.0)
  * `docs/ETAPA_01_FUNDACAO_E_SEGURANCA.md` (Especificação Auditável da Etapa 1)
  * `docs/GUIA_SEGURANCA_E_REDE.md` (Manual de Segurança e Rede elaborado pelo Orquestrador para o Arquiteto Técnico)

## Como Executar Localmente

1. Crie um ambiente virtual Python (3.11+) e instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Execute a suíte de testes automatizados para validar o ambiente:
   ```bash
   python -m unittest discover -s tests -v
   ```
3. Inicie a aplicação Web:
   ```bash
   python run.py
   ```
4. Acesse `http://127.0.0.1:8000` no navegador usando uma das contas iniciais:
   * **Perfil ADMIN (Gestão de Credenciais e Certificados):** `admin@escritorio.cnt.br` | Senha: `Admin@2026!`
   * **Perfil FISCAL (Operação e Conciliação Fiscal):** `fiscal@escritorio.cnt.br` | Senha: `Fiscal@2026!`
