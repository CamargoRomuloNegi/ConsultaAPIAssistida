# Guia de Segurança da Informação e Rede — Apuração Assistida CBS (Receita Federal)

**Autores:** Arquiteto Técnico (Diretrizes) & Gemini (Orquestrador Técnico e Engenharia de Segurança/Rede)  
**Data:** 28/10/2026

Este guia foi elaborado pelo Orquestrador Técnico para cobrir integralmente as exigências de **segurança da informação, criptografia, certificados digitais e infraestrutura de rede** exigidas pela Receita Federal no [Guia de APIs Assíncronas da CBS](https://docs.receitafederal.gov.br/apuracao-cbs/guiaapiassincrona.html) e na documentação do [Receita Integra](https://midias-totvs.totvs.com/wp-content/uploads/2026/09/08151540/Receita-Integra-Documentacao-Tecnica-Prod-v1.4.pdf).

## 1. Como Evitar Complexidade de Firewall e Rede no Escritório Contábil (Modo Polling vs. Webhook)

A dúvida de rede mais comum ao integrar com a API assíncrona da Receita Federal é sobre o campo `urlRetorno` (Webhook).

| Modalidade | Como Funciona | Impacto na Rede do Escritório Contábil | Recomendação Arquitetural |
| :--- | :--- | :--- | :--- |
| **Modo Polling (`"urlRetorno": ""`)** | Nosso sistema envia `urlRetorno` vazio na abertura (`POST /debitos/{cnpj}`) e consulta periodicamente `GET /situacao/{tiquete}` até o status mudar para `CONCLUIDA`. | **Zero abertura de portas de entrada!** O computador/servidor do escritório faz apenas chamadas normais de saída (`HTTPS Outbound` porta 443), exatamente como navegar em um site. | **Padrão adotado no nosso sistema.** Ideal para rodar localmente ou em servidor interno sem precisar de IP fixo público, DNS próprio ou regras de NAT/WAF. |
| **Modo Webhook (`"urlRetorno": "https://..."`)** | A Receita Federal faz um teste `HEAD` imediato no seu servidor e depois envia um `POST` quando o arquivo fica pronto. | Exige domínio público com certificado TLS válido e liberação de entrada no firewall exclusivamente para o IP oficial da Receita Federal (`189.9.61.23/32`). | Suportado opcionalmente pelo nosso sistema (rota `/webhooks/rfb/apuracao-cbs` já blindada com filtro de IP), mas desnecessário para operação local. |

## 2. As 4 Camadas de Segurança Implementadas no Código (Etapa 1)

### 2.1. Cofre Criptográfico em Repouso (`SecretVault` — AES-128-CBC + HMAC-SHA256)
* O `client_secret` gerado no portal da Receita Federal e a senha do certificado digital `.pfx` **nunca são gravados em texto puro** no arquivo SQLite (`apuracao_cbs.db`).
* O módulo `app/core/security.py` utiliza criptografia simétrica autenticada **Fernet** (`cryptography.fernet`), que combina **AES-128 em modo CBC** com assinatura **HMAC-SHA256**.
* A chave mestra é gerada automaticamente em `data/.master.key` com permissão restrita ao usuário do sistema operacional (`chmod 0600`) ou pode ser injetada via variável de ambiente `CBS_MASTER_KEY`.

### 2.2. Inspeção e Isolamento de Certificados Digitais ICP-Brasil (A1 `.pfx` / `.p12`)
* Ao anexar o certificado `.pfx` de um cliente na tela de Administração, o `CertificateInspector` valida imediatamente:
  1. Se a senha informada abre o cofre PKCS#12;
  2. Se há chave privada válida e certificado X.509 íntegro;
  3. Qual é o CNPJ contido no *Common Name* (`Subject CN`) e quantos dias faltam para o vencimento (`not_valid_after`), gravando o arquivo em diretório isolado (`data/vault_certs/`).

### 2.3. Sanitização Automática Contra Vazamento de `urlAssinada` e Tokens (`SensitiveDataLogFilter`)
* A seção 5.1 do [Guia de APIs Assíncronas da RFB](https://docs.receitafederal.gov.br/apuracao-cbs/guiaapiassincrona.html) determina expressamente:
  > *"Proteger a urlAssinada: tratar a URL Assinada como um segredo temporário, pois ela autoriza o download durante o período de validade de 48 horas. Não gravá-la em logs, mensagens de erro, métricas, histórico do navegador..."*
* Para garantir que nenhum erro de rede acabe gravando a URL pré-assinada do S3 ou o `Bearer Token` no console ou no banco, implementamos o filtro `SensitiveDataLogFilter` em `app/core/network_security.py`. Qualquer string contendo `Bearer ...`, `X-Amz-Signature=...` ou `client_secret=...` é automaticamente substituída por máscaras seguras antes de ir para o log ou para a tabela `audit_logs`.

### 2.4. Segregação Estrita de Papéis (RBAC: `ADMIN` vs. `FISCAL`)
* O Analista Fiscal (`FISCAL`) pode cadastrar clientes/filiais, acompanhar o **Semáforo da Janela de 8 Dias**, consultar a apuração assistida e auditar XMLs/CSVs.
* Porém, toda a gestão de credenciais OAuth2 (`client_id` / `client_secret`), certificados digitais `.pfx` e usuários do escritório é bloqueada no backend (`HTTP 403 Forbidden`) para qualquer sessão que não possua o papel `ADMIN`.
