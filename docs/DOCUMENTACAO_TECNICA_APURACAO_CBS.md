# Documentação Técnica e Arquitetural — Sistema de Auditoria e Confronto da Apuração Assistida (CBS / IBS)

**Versão do Documento:** 1.1.0 (Etapa 1 Implementada e Validada)  
**Data de Atualização:** 28/10/2026  
**Escopo:** Escritório Contábil Multi-Cliente (Multi-Tenant) — Consulta Assíncrona à API da Receita Federal (`v2`) e Motor de Conciliação Fiscal (XMLs e CSV)

## Governança e Autoria do Projeto

Em honra ao trabalho colaborativo de concepção, arquitetura e engenharia deste sistema, registra-se formalmente a matriz de responsabilidades do projeto:

| Papel no Projeto | Responsável | Atribuições e Responsabilidades |
| :--- | :--- | :--- |
| **Arquiteto Técnico** | **Titular do Projeto (Usuário)** | Concepção estratégica do produto, definição das premissas de negócio para Escritórios Contábeis Multi-Cliente, diretrizes de segregação de acesso (RBAC), recorte de escopo fiscal da Reforma Tributária (CBS/IBS) e validação arquitetural de cada etapa. |
| **Orquestrador Técnico & Engenharia de Segurança/Software** | **Gemini (Google AI)** | Levantamento técnico da documentação da Receita Federal (`docs.receitafederal.gov.br/apuracao-cbs`), engenharia de segurança da informação e de rede (TLS 1.2+, Cofre Criptográfico Fernet, Certificados ICP-Brasil A1, sanitização de logs e proteção de Webhook), implementação em Python e documentação técnica incremental. |

## 1. Visão Geral e Objetivo do Projeto

Este documento constitui o registro técnico, incremental e auditável do projeto de conciliação da **Apuração Assistida da Contribuição sobre Bens e Serviços (CBS)**, instituída pela [Lei Complementar nº 214/2025](https://www.planalto.gov.br/ccivil_03/leis/lcp/lcp214.htm) (art. 46) e regulamentada pelo Decreto nº 12.955/2026.

O sistema é desenhado para a realidade de um **escritório contábil que gerencia múltiplos clientes (CNPJs matrizes)**, permitindo:
1. **Gestão Segregada de Acessos e Credenciais (RBAC):** Separação estrita entre o perfil **Administrador** (responsável pelo cofre de credenciais `client_id`/`client_secret` do Receita Integra e certificados digitais ICP-Brasil A1) e o perfil **Analista Fiscal** (responsável pela execução das consultas, importação de XMLs/CSVs e auditoria de divergências).
2. **Consumo Resiliente e Incremental da API da Receita Federal (`v2`):** Orquestração do ciclo assíncrono em 4 etapas documentado no [Portal da Apuração CBS](https://docs.receitafederal.gov.br/apuracao-cbs/), respeitando os limites severos de cota (2 tokens/hora e 4 solicitações/dia por API) e reconstruindo a base mensal a partir das janelas móveis de 8 dias.
3. **Motores de Regras Independentes por Modelo de DF-e:** Extração focada exclusivamente nas tags da Reforma Tributária (`<IBSCBS>`, `<gIBSCBS>`, `<gCBS>`, `<vCBS>`, `<vIBS>`, `<CST>`, `<cClassTrib>`) com parsers desacoplados para **NF-e (55)**, **NFC-e (65)**, **CT-e (57)** e **NFS-e Padrão Nacional (91)**, além de conector parametrizável para arquivos `.csv`.
4. **Confronto Automatizado (Cruzamento Nota a Nota):** Identificação imediata de documentos presentes na Apuração Assistida e ausentes na escrituração própria, documentos presentes na escrituração e ausentes na Receita Federal, e divergências de valores apurados, suspensos, inexigíveis ou extintos.

## 2. Especificação da Integração com a API da Receita Federal (v2)

A integração segue os contratos publicados no [Guia Comum das APIs Assíncronas](https://docs.receitafederal.gov.br/apuracao-cbs/guiaapiassincrona.html) (versão 1.1 de 14/10/2026) e no manual técnico da plataforma [Receita Integra](https://midias-totvs.totvs.com/wp-content/uploads/2026/09/08151540/Receita-Integra-Documentacao-Tecnica-Prod-v1.4.pdf) (versão 1.4).

### 2.1. Ambientes e Rotas Oficiais

| Serviço / Domínio | Método | Endpoint (Produção / Produção Beta) | Endpoint (Produção Restrita - PRR) | Status RFB |
| :--- | :--- | :--- | :--- | :--- |
| **Autenticação OAuth2** | `POST` | `https://api.receitafederal.gov.br/token` | `https://api.receitafederal.gov.br/token` | Ativo |
| **[Consulta de Débitos](https://docs.receitafederal.gov.br/apuracao-cbs/debito.html)** | `POST` | `/apuracao-cbs/v2/debitos/{cnpj}` | `/apuracao-cbs-prr/v2/debitos/{cnpj}` | Ativo (Out/2026) |
| **[Consulta de Créditos](https://docs.receitafederal.gov.br/apuracao-cbs/credito.html)** | `POST` | `/apuracao-cbs/v2/creditos/{cnpj}` | `/apuracao-cbs-prr/v2/creditos/{cnpj}` | Ativo (Out/2026) |
| **[Situação da Solicitação](https://docs.receitafederal.gov.br/apuracao-cbs/situacao-solicitacao.html)** | `GET` | `/apuracao-cbs/v2/situacao/{tiqueteSolicitacao}` | `/apuracao-cbs-prr/v2/situacao/{tiqueteSolicitacao}` | Ativo (Out/2026) |
| **[Link de Download (S3)](https://docs.receitafederal.gov.br/apuracao-cbs/download.html)** | `GET` | `/apuracao-cbs/v2/download/{tiqueteSolicitacao}` | `/apuracao-cbs-prr/v2/download/{tiqueteSolicitacao}` | Ativo (Out/2026) |
| **[Consulta de Pagamentos](https://docs.receitafederal.gov.br/apuracao-cbs/pagamentos.html)** | `POST` | `/apuracao-cbs/v2/pagamentos/{cnpj}` | `/apuracao-cbs-prr/v2/pagamentos/{cnpj}` | Previsto Nov/2026 |
| **[Consulta de Recolhimentos](https://docs.receitafederal.gov.br/apuracao-cbs/recolhimentos.html)** | `POST` | `/apuracao-cbs/v2/recolhimentos/{cnpj}` | `/apuracao-cbs-prr/v2/recolhimentos/{cnpj}` | Previsto Nov/2026 |

### 2.2. Regras de Negócio, Segurança e Rede Cobre-Falhas

| Regra / Limite | Especificação Oficial ([FAQ Apuração CBS](https://docs.receitafederal.gov.br/apuracao-cbs/faq.html)) | Tratamento Arquitetural no Nosso Sistema |
| :--- | :--- | :--- |
| **Identificador do Contribuinte** | Path `{cnpj}` exige exatamente os **8 dígitos da raiz (CNPJ básico)** da matriz | Validação e sanitização automática do CNPJ; agrupamento de filiais sob a raiz da matriz no cadastro de clientes |
| **Dispensa de Abertura de Firewall** | Campo `urlRetorno` no `POST` aceita string vazia `""` para operar sem Webhook | **Modo Polling como padrão:** o escritório faz apenas conexões de saída HTTPS (porta 443), dispensando IP fixo, DNS público ou abertura de portas no roteador/firewall |
| **Blindagem de Webhook (Opcional)** | Se `urlRetorno` for usada, a RFB valida com `HEAD` e envia `POST` a partir do IP `189.9.61.23/32` | Rota `/webhooks/rfb/apuracao-cbs` implementada com suporte a `HEAD` e bloqueio automático (`HTTP 403`) para qualquer IP fora da Allowlist oficial (`189.9.61.23/32`) |
| **Proteção de Credenciais e `urlAssinada`** | O arquivo no S3 vale por 48h; é proibido gravar `urlAssinada` ou `Bearer` em logs | Cofre `SecretVault` (AES-128-CBC + HMAC-SHA256) para `client_secret` e senhas `.pfx` em repouso + filtro `SensitiveDataLogFilter` que mascara `Bearer` e `X-Amz-Signature` em tempo real |
| **Limite de Tokens e Cotas** | Máximo de **2 tokens/hora** e **4 chamadas/dia por API** | Tabelas `api_credentials` e `api_quota_ledger` preparadas para controle estrito de cache de token e bloqueio preventivo de excesso de chamadas |
| **Janela Incremental de 8 Dias** | Com consulta nos últimos 3 meses, retorna alterações limitadas aos **últimos 8 dias** | **Semáforo da Janela de 8 Dias** (`VERDE`, `AMARELO`, `VERMELHO_HIATO`, `AZUL_INICIAL`) já ativo no Painel de Clientes da Etapa 1 |

## 3. Decisão de Banco de Dados Local e Stack Tecnológica

* **Banco de Dados Local:** **SQLite 3 em Modo WAL (`PRAGMA journal_mode=WAL;`)** com DDL SQL explícito (`app/core/database.py`) e contratos de domínio validados com **Pydantic v2** (`app/models/schemas.py`).
  * *Vantagem para manutenção e futura migração:* Zero dependência de servidores externos, backup em arquivo único (`data/apuracao_cbs.db`) e SQL 100% explícito e documentado, facilitando a futura conversão para C#, Java, Node.js ou PostgreSQL.
* **Stack Web e Segurança:** **FastAPI + Jinja2 + Cryptography (Fernet / PKCS#12 X.509)**, com sessões assinadas via `HMAC-SHA256` (`HttpOnly`) e senhas com hash `PBKDF2-HMAC-SHA256` (390.000 iterações).

## 4. Arquitetura dos Motores de Regras de XML (Por Modelo de DF-e)

O parser utiliza o padrão de projeto **Strategy (Um Motor de Regras por Modelo)**, extraindo apenas o **Envelope de Identificação** e o **Bloco Tributário da Reforma (CBS/IBS)**:

| Modelo de DF-e | Base Normativa | Identificação (Chave, Data, Emitente, Finalidade) | Tags de Item (`IBSCBS`) | Tags Totalizadoras do Documento (`vCBS` / `vIBS`) |
| :--- | :--- | :--- | :--- | :--- |
| **NF-e (55)** | [NT 2025.002-RTC v1.52](https://www.nfe.fazenda.gov.br/portal/exibirArquivo.aspx?conteudo=HXPO8VLbh4o=) | `infNFe/@Id` (44 díg.), `ide/mod` (`55`), `ide/dhEmi`, `ide/finNFe` (`5`=Crédito, `6`=Débito), `emit/CNPJ`, `dest/CNPJ` | `det/imposto/IBSCBS/CST`, `cClassTrib`, `gIBSCBS/vBC`, `gIBSCBS/gCBS/pCBS`, `gIBSCBS/gCBS/vCBS`, `gIBSCBS/gDif/vDif`, `gIBSCBS/gDevTrib/vDevTrib` | `total/IBSCBSTot/vBCIBSCBS`, `total/IBSCBSTot/gCBS/vCBS`, `gCBS/vDif`, `gCBS/vDevTrib`, `gCBS/vCredPres`, `total/IBSCBSTot/gIBS/vIBS` |
| **NFC-e (65)** | [NT 2025.002-RTC v1.52](https://www.nfe.fazenda.gov.br/portal/exibirArquivo.aspx?conteudo=HXPO8VLbh4o=) | `infNFe/@Id` (44 díg.), `ide/mod` (`65`), `ide/dhEmi`, `ide/finNFe`, `emit/CNPJ`, `dest/CNPJ` ou `CPF` | Mesma estrutura do grupo `det/imposto/IBSCBS` da NF-e | `total/IBSCBSTot/vBCIBSCBS`, `total/IBSCBSTot/gCBS/vCBS`, `total/IBSCBSTot/gIBS/vIBS` |
| **CT-e (57)** | [NT 2025.001-RTC](https://www.reformatributaria.com/wp-content/uploads/2025/09/CTe_Nota_Tecnica_2025_001_RTC_v1.09.pdf) | `infCte/@Id` (44 díg.), `ide/mod` (`57`), `ide/dhEmi`, `ide/tpCTe`, `emit/CNPJ`, `rem/CNPJ`, `toma` | `infCte/imp/IBSCBS/CST`, `cClassTrib`, `gIBSCBS/vBC`, `gIBSCBS/gCBS/pCBS`, `gIBSCBS/gCBS/vCBS`, `gIBSCBS/gCBSCredPres/vCredPres` | `infCte/imp/IBSCBS/gIBSCBS/gCBS/vCBS` e `infCte/imp/vTotDFe` |
| **NFS-e Nacional (91)** | [NT SE/CGNFS-e 004 v2.0](https://www.gov.br/nfse/pt-br/biblioteca/documentacao-tecnica/producao-restrita/nt-004-se-cgnfse-novo-layout-rtc-v2-00-20251210.pdf) e NT 009 | `infNFSe/@Id` (50 díg.), `DPS/infDPS/dhEmi`, `DPS/infDPS/prest/CNPJ`, `toma/CNPJ`, `IBSCBS/finNFSe` (`0`=Regular, `1`=Crédito, `2`=Débito) | Declarado na DPS: `DPS/infDPS/IBSCBS/cIndOp`, `valores/trib/gIBSCBS/CST`, `cClassTrib`, `gDif/pDifCBS` | Calculado pelo ADN em `infNFSe/IBSCBS`: `valores/vBC`, `valores/fed/pAliqEfetCBS`, `totCIBS/gCBS/vCBS`, `totCIBS/gCBS/vDifCBS`, `totCIBS/gIBS/vIBSTot` |

## 5. Roteiro de Construção Incremental e Status Atual

| Etapa | Escopo Técnico | Status | Pacote / Entregável |
| :--- | :--- | :--- | :--- |
| **Etapa 1** | Fundação, Banco SQLite (WAL), Gestão Multi-Cliente (Matriz 8 díg. / Filiais 14 díg.), Cofre Criptografado de Credenciais/Certificados A1, Blindagem de Rede/Logs e Login RBAC (`ADMIN` vs. `FISCAL`) | **CONCLUÍDA E TESTADA** | `apuracao_cbs_etapa1_fundacao_seguranca.zip` (`docs/ETAPA_01_FUNDACAO_E_SEGURANCA.md` + `docs/GUIA_SEGURANCA_E_REDE.md`) |
| **Etapa 2** | Conector OAuth2 Receita Integra (cache 2/h), Máquina de Estados Assíncrona (`POST` $\rightarrow$ `situacao` $\rightarrow$ `download` $\rightarrow$ `S3`), Guardião de Cota (4/dia) e Modo Simulador Oficial (Mock) | Próxima Etapa | `ETAPA_02_CONECTOR_API_RFB.md` |
| **Etapa 3** | Consolidador Incremental de Débitos CBS (Upsert por `chave` + `origem` + `pa` para recompor o mês completo a partir das janelas de 8 dias) | Planejada | `ETAPA_03_CONSOLIDACAO_INCREMENTAL.md` |
| **Etapa 4** | Motores de Regras Independentes de XML (`55`, `65`, `57`, `91`) focados em CBS/IBS + Importador Parametrizável de `.csv` | Planejada | `ETAPA_04_MOTORES_XML_E_CSV.md` |
| **Etapa 5** | Motor de Confronto (RFB vs. Escrituração), Dashboard de Divergências Nota a Nota e Exportação de Relatórios Auditáveis (CSV/Excel) | Planejada | `ETAPA_05_MOTOR_CONFRONTO_AUDITORIA.md` |
