#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ponto de entrada para execução local do servidor Web da Apuração Assistida CBS.

Governança Técnica:
- Arquiteto Técnico: Responsável pela visão de negócio contábil, diretrizes fiscais e validação arquitetural.
- Orquestrador Técnico & Engenharia (Gemini): Implementação de segurança, rede, banco de dados e código Python.
"""

import uvicorn
from app.core.database import init_db

if __name__ == "__main__":
    print("Inicializando banco de dados SQLite (Modo WAL) e estruturas de segurança...")
    init_db()
    print("Servidor iniciando em http://127.0.0.1:8000")
    print("Credenciais iniciais de demonstração:")
    print("  [Perfil ADMIN]  Usuário: admin@escritorio.cnt.br  | Senha: Admin@2026!")
    print("  [Perfil FISCAL] Usuário: fiscal@escritorio.cnt.br | Senha: Fiscal@2026!")
    uvicorn.run("app.web.main:app", host="127.0.0.1", port=8000, reload=False)
