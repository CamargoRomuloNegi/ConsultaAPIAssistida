# -*- coding: utf-8 -*-
"""
Modelos de dados validados via Pydantic (compatível tanto com Pydantic v1 quanto v2)
para contratos de entrada/saída e regras de domínio.
"""

import re
from typing import Optional
from pydantic import BaseModel, Field

try:
    from pydantic import field_validator as _validator

    PYDANTIC_V2 = True
except ImportError:
    from pydantic import validator as _validator

    PYDANTIC_V2 = False


def clean_digits(val: str) -> str:
    return re.sub(r"\D", "", val or "")


class CompatModel(BaseModel):
    """Classe base que oferece `.to_dict()` compatível entre Pydantic v1 e v2."""

    def to_dict(self) -> dict:
        if hasattr(self, "model_dump"):
            return self.model_dump()
        return self.dict()


class ClientCreateInput(CompatModel):
    """Dados para cadastro de um novo cliente (Estabelecimento Matriz) no escritório contábil."""

    cnpj_matriz_completo: str = Field(..., description="CNPJ completo da Matriz (14 dígitos)")
    razao_social: str = Field(..., min_length=3, max_length=150)
    regime_tributario: str = Field(default="REGIME_REGULAR")
    responsavel_fiscal: str = Field(default="")
    uf_matriz: str = Field(default="SP", min_length=2, max_length=2)
    municipio_matriz: str = Field(default="São Paulo")

    @_validator("cnpj_matriz_completo")
    @classmethod
    def validate_cnpj(cls, v: str) -> str:
        digits = clean_digits(v)
        if len(digits) != 14:
            raise ValueError("O CNPJ da matriz deve conter exatamente 14 dígitos numéricos.")
        return digits

    @property
    def cnpj_base(self) -> str:
        """Retorna os 8 dígitos da raiz do CNPJ (exigido no path da API da Receita Federal)."""
        return self.cnpj_matriz_completo[:8]


class BranchCreateInput(CompatModel):
    """Dados para vinculação de uma filial (14 dígitos) a um cliente matriz (8 dígitos)."""

    client_id: int
    cnpj_completo: str
    nome_fantasia: str = Field(..., min_length=2, max_length=120)
    uf: str = Field(..., min_length=2, max_length=2)
    municipio: str = Field(..., min_length=2, max_length=100)

    @_validator("cnpj_completo")
    @classmethod
    def validate_cnpj_filial(cls, v: str) -> str:
        digits = clean_digits(v)
        if len(digits) != 14:
            raise ValueError("O CNPJ da filial deve conter exatamente 14 dígitos numéricos.")
        return digits


class CredentialUpsertInput(CompatModel):
    """
    Dados de configuração de credencial OAuth2 (Receita Integra) e Webhook para um cliente.
    Operação restrita exclusivamente ao perfil ADMIN.
    """

    client_id: int
    ambiente: str = Field(default="PRODUCAO")
    oauth_client_id: str = Field(..., min_length=3, max_length=120)
    oauth_client_secret: str = Field(..., min_length=4, max_length=256)
    webhook_url_retorno: str = Field(default="")

    @_validator("ambiente")
    @classmethod
    def validate_ambiente(cls, v: str) -> str:
        v_up = v.strip().upper()
        if v_up not in ("PRODUCAO", "PRR"):
            raise ValueError("Ambiente deve ser PRODUCAO ou PRR (Produção Restrita).")
        return v_up

    @_validator("webhook_url_retorno")
    @classmethod
    def validate_webhook(cls, v: str) -> str:
        v_clean = (v or "").strip()
        if v_clean and not v_clean.startswith("https://"):
            raise ValueError(
                "Conforme seção 5.1 do Guia de APIs Assíncronas da RFB, a urlRetorno (webhook) deve usar exclusivamente HTTPS (ou ser vazia '')."
            )
        return v_clean


class SyncWindowStatus(CompatModel):
    """Representa o Semáforo da Janela Incremental de 8 Dias da Receita Federal por cliente."""

    status_code: str  # VERDE, AMARELO, VERMELHO_HIATO, AZUL_INICIAL
    badge_label: str
    dias_desde_ultima_consulta: Optional[int]
    explicacao_regra_rfb: str
