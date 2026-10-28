# -*- coding: utf-8 -*-
"""
Módulo de Blindagem de Rede, Sanitização de Logs e Segurança de Transporte (TLS/Webhook).

Objetivo Arquitetural:
Cobrir integralmente os requisitos de segurança da informação e de rede exigidos pela
Receita Federal na seção 5.1 e 5.2 do Guia de APIs Assíncronas:
1. Mascaramento automático de tokens OAuth2, client_secret e URLs pré-assinadas (S3 urlAssinada)
   em qualquer log de aplicação ou trilha de erro.
2. Validação de origem de IP (Allowlist CIDR 189.9.61.23/32) para o endpoint de Webhook.
3. Contexto TLS seguro (TLS 1.2 / TLS 1.3) com suporte opcional a certificado mTLS e Proxy Corporativo.
4. Diagnóstico automatizado de segurança e rede para apoio ao Arquiteto Técnico.
"""

import ipaddress
import logging
import os
import re
import ssl
from typing import Dict, Any, List

from app.core.config import (
    RFB_WEBHOOK_ALLOWED_CIDRS_PRODUCAO,
    RFB_WEBHOOK_ALLOWED_CIDRS_PRR,
    DATA_DIR,
    VAULT_CERTS_DIR,
)

# Expressões regulares para interceptar e mascarar dados sensíveis antes de qualquer gravação em log
REGEX_BEARER_TOKEN = re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)
REGEX_S3_SIGNED_URL = re.compile(
    r'(https?://[^\s"\'<>]+(?:X-Amz-Signature|X-Amz-Credential|Signature)=[^\s"\'<>]+)',
    re.IGNORECASE,
)
REGEX_CLIENT_SECRET = re.compile(
    r'(["\']?(?:client_secret|senha|password|cert_password)["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)(["\']?)',
    re.IGNORECASE,
)


def mask_sensitive_text(text: str) -> str:
    """
    Remove e mascara tokens Bearer, segredos OAuth2 e URLs pré-assinadas (urlAssinada S3)
    de qualquer string antes de exibi-la ou registrá-la em log.
    """
    if not text:
        return text
    sanitized = REGEX_BEARER_TOKEN.sub(r"\1***[TOKEN_MASCARADO]***", text)
    sanitized = REGEX_S3_SIGNED_URL.sub(
        "https://[STORAGE_S3_PROTEGIDO]/[URL_ASSINADA_TEMPORARIA_MASCARADA]",
        sanitized,
    )
    sanitized = REGEX_CLIENT_SECRET.sub(r"\1***[SEGREDO_MASCARADO]***\3", sanitized)
    return sanitized


class SensitiveDataLogFilter(logging.Filter):
    """
    Filtro nativo do módulo `logging` do Python que garante que nenhuma mensagem de log
    grave credenciais, tokens Bearer ou `urlAssinada` em texto aberto.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: mask_sensitive_text(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    mask_sensitive_text(str(arg)) if isinstance(arg, str) else arg
                    for arg in record.args
                )
        return True


def configure_secure_logger(name: str = "apuracao_cbs") -> logging.Logger:
    """Retorna um logger configurado com o filtro de mascaramento de segredos ativo."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataLogFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    for f in logger.filters:
        if isinstance(f, SensitiveDataLogFilter):
            break
    else:
        logger.addFilter(SensitiveDataLogFilter())
    return logger


def validate_rfb_webhook_ip(client_ip: str, ambiente: str = "PRODUCAO") -> bool:
    """
    Verifica se o endereço IP de origem que acionou o nosso endpoint de Webhook
    pertence à faixa oficial publicada pela Receita Federal (189.9.61.23/32 em Produção).
    """
    try:
        ip_obj = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False

    allowed_cidrs: List[str] = (
        RFB_WEBHOOK_ALLOWED_CIDRS_PRODUCAO
        if ambiente.upper() == "PRODUCAO"
        else RFB_WEBHOOK_ALLOWED_CIDRS_PRR
    )
    for cidr in allowed_cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        if ip_obj in network:
            return True
    return False


def create_secure_ssl_context(cert_pem_path: str = "", key_pem_path: str = "") -> ssl.SSLContext:
    """
    Cria um contexto SSL/TLS endurecido (Hardened TLS):
    - Exige no mínimo TLS 1.2 (compatível com TLS 1.3).
    - Desabilita protocolos legados inseguros (SSLv2, SSLv3, TLSv1.0, TLSv1.1).
    - Mantém verificação obrigatória de certificado do servidor e hostname.
    - Permite anexar certificado digital ICP-Brasil (mTLS) quando exigido pelo gateway.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    if cert_pem_path and key_pem_path and os.path.exists(cert_pem_path) and os.path.exists(key_pem_path):
        ctx.load_cert_chain(certfile=cert_pem_path, keyfile=key_pem_path)

    return ctx


def run_network_and_security_diagnostics() -> Dict[str, Any]:
    """
    Executa uma bateria de testes locais de segurança e configuração de rede para dar
    visibilidade completa ao Arquiteto Técnico na interface Web.
    """
    ssl_ctx = create_secure_ssl_context()
    sample_leak = (
        "Header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.segredo "
        "Download: https://s3.gov.br/arq.json?X-Amz-Signature=abcdef12345 "
        "client_secret='meu_segredo_super_secreto'"
    )
    masked_sample = mask_sensitive_text(sample_leak)
    mask_working = (
        "eyJhbGciOiJIUzI1NiJ9" not in masked_sample
        and "abcdef12345" not in masked_sample
        and "meu_segredo_super_secreto" not in masked_sample
    )

    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "Não configurado (Conexão Direta)"

    return {
        "openssl_version": ssl.OPENSSL_VERSION,
        "tls_min_version": ssl_ctx.minimum_version.name,
        "cert_verification": "Obrigatória (CERT_REQUIRED + Check Hostname)",
        "operation_mode_default": 'Polling Assíncrono (urlRetorno = "") — Dispensa abrir portas de entrada no Firewall',
        "webhook_ip_allowlist_prod": RFB_WEBHOOK_ALLOWED_CIDRS_PRODUCAO,
        "webhook_ip_validation_test": {
            "ip_oficial_rfb_189_9_61_23": validate_rfb_webhook_ip("189.9.61.23", "PRODUCAO"),
            "ip_externo_nao_autorizado_8_8_8_8": validate_rfb_webhook_ip("8.8.8.8", "PRODUCAO"),
        },
        "log_sanitization_active": mask_working,
        "log_sanitization_demo": masked_sample,
        "proxy_detected": https_proxy,
        "vault_directory_exists": VAULT_CERTS_DIR.exists(),
        "data_directory_exists": DATA_DIR.exists(),
    }
