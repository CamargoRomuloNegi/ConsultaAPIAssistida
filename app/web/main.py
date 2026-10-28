# -*- coding: utf-8 -*-
"""
Aplicação Web FastAPI — Etapa 1 (Fundação, Controle de Acesso Segregado RBAC,
Gestão Multi-Cliente Matriz/Filiais, Cofre de Credenciais/Certificados e Segurança de Rede).
"""

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.core.config import SESSION_COOKIE_NAME
from app.core.database import init_db
from app.core.network_security import (
    configure_secure_logger,
    validate_rfb_webhook_ip,
    run_network_and_security_diagnostics,
)
from app.core.security import SessionManager, SecretVault
from app.models.schemas import ClientCreateInput, BranchCreateInput, CredentialUpsertInput
from app.services.repository import OfficeRepository

logger = configure_secure_logger("apuracao_cbs.web")

app = FastAPI(
    title="Sistema de Auditoria Apuração Assistida CBS/IBS — Receita Federal",
    description="Etapa 1: Fundação, Cofre de Credenciais/Certificados, Blindagem de Rede e Controle de Acesso (RBAC)",
    version="1.0.0",
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

vault = SecretVault()
session_mgr = SessionManager(vault=vault)
repo = OfficeRepository(vault=vault)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    return session_mgr.verify_session_token(token)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, msg: str = "", erro: str = ""):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "msg": msg, "erro": erro},
    )


@app.post("/login")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = repo.authenticate_user(email=email, password=password, ip_address=client_ip)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "erro": "Credenciais inválidas. Verifique seu e-mail e senha.", "msg": ""},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    token = session_mgr.create_session_token(
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        nome=user["nome"],
    )
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login?msg=Sessão+encerrada+com+segurança", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, msg: str = "", erro: str = ""):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    clients = repo.list_clients_with_status()
    diagnostics = run_network_and_security_diagnostics()
    audit_logs = repo.list_audit_logs(limit=25)
    users_list = repo.list_users() if user["role"] == "ADMIN" else []

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "clients": clients,
            "diagnostics": diagnostics,
            "audit_logs": audit_logs,
            "users_list": users_list,
            "msg": msg,
            "erro": erro,
        },
    )


@app.post("/clientes/novo")
def cadastrar_cliente(
    request: Request,
    cnpj_matriz_completo: str = Form(...),
    razao_social: str = Form(...),
    regime_tributario: str = Form("REGIME_REGULAR"),
    responsavel_fiscal: str = Form(""),
    uf_matriz: str = Form("SP"),
    municipio_matriz: str = Form("São Paulo"),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    try:
        inp = ClientCreateInput(
            cnpj_matriz_completo=cnpj_matriz_completo,
            razao_social=razao_social,
            regime_tributario=regime_tributario,
            responsavel_fiscal=responsavel_fiscal or user["email"],
            uf_matriz=uf_matriz,
            municipio_matriz=municipio_matriz,
        )
        repo.create_client(inp, actor_email=user["email"], actor_role=user["role"])
        return RedirectResponse(
            url=f"/?msg=Cliente+{inp.razao_social}+(Raiz+{inp.cnpj_base})+cadastrado+com+sucesso!",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            url=f"/?erro={str(exc)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )


@app.post("/clientes/filial")
def cadastrar_filial(
    request: Request,
    client_id: int = Form(...),
    cnpj_completo: str = Form(...),
    nome_fantasia: str = Form(...),
    uf: str = Form("SP"),
    municipio: str = Form("São Paulo"),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    try:
        inp = BranchCreateInput(
            client_id=client_id,
            cnpj_completo=cnpj_completo,
            nome_fantasia=nome_fantasia,
            uf=uf,
            municipio=municipio,
        )
        repo.add_branch(inp, actor_email=user["email"], actor_role=user["role"])
        return RedirectResponse(
            url=f"/?msg=Filial+{inp.cnpj_completo}+vinculada+com+sucesso!",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(url=f"/?erro={str(exc)}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/credenciais")
async def salvar_credenciais_cofre(
    request: Request,
    client_id: int = Form(...),
    ambiente: str = Form("PRODUCAO"),
    oauth_client_id: str = Form(...),
    oauth_client_secret: str = Form(...),
    webhook_url_retorno: str = Form(""),
    pfx_password: str = Form(""),
    pfx_file: Optional[UploadFile] = File(None),
):
    """
    Rota exclusiva para o perfil ADMIN: grava ou rotaciona `client_id` e `client_secret`
    no cofre Fernet e valida o certificado ICP-Brasil (.pfx) se enviado.
    """
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    if user["role"] != "ADMIN":
        repo.log_audit(
            user["email"],
            user["role"],
            "RBAC_BLOQUEIO_COFRE",
            f"client_id:{client_id}",
            "Usuário com perfil FISCAL tentou acessar rota exclusiva de administração de credenciais.",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado (RBAC): Apenas usuários com perfil ADMIN podem gerenciar credenciais e certificados.",
        )

    try:
        pfx_bytes = None
        pfx_name = ""
        if pfx_file and pfx_file.filename:
            pfx_bytes = await pfx_file.read()
            pfx_name = pfx_file.filename

        inp = CredentialUpsertInput(
            client_id=client_id,
            ambiente=ambiente,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
            webhook_url_retorno=webhook_url_retorno,
        )
        repo.upsert_api_credentials(
            data=inp,
            actor_email=user["email"],
            actor_role=user["role"],
            pfx_bytes=pfx_bytes,
            pfx_filename=pfx_name,
            pfx_password=pfx_password,
        )
        return RedirectResponse(
            url="/?msg=Credenciais+e+Certificado+atualizados+e+criptografados+no+Cofre+com+sucesso!",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(url=f"/?erro={str(exc)}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/usuarios")
def criar_usuario_escritorio(
    request: Request,
    nome: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("FISCAL"),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    if user["role"] != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: apenas ADMIN pode gerenciar usuários.",
        )

    try:
        repo.create_user(
            nome=nome,
            email=email,
            password=password,
            role=role,
            actor_email=user["email"],
            actor_role=user["role"],
        )
        return RedirectResponse(
            url=f"/?msg=Usuário+{email}+({role})+cadastrado+com+sucesso!",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(url=f"/?erro={str(exc)}", status_code=status.HTTP_303_SEE_OTHER)


@app.head("/webhooks/rfb/apuracao-cbs")
def webhook_rfb_head_check(request: Request):
    """
    Responde à chamada HEAD de validação de disponibilidade feita pela Receita Federal
    no momento da abertura da solicitação assíncrona quando `urlRetorno` é informada.
    """
    return JSONResponse(content={"status": "ok"}, status_code=status.HTTP_200_OK)


@app.post("/webhooks/rfb/apuracao-cbs")
async def webhook_rfb_notification(request: Request):
    """
    Recebe a notificação assíncrona da Receita Federal (`tiqueteSolicitacao` e `situacao`
    ou `codigoErro` e `mensagemErro`), validando estritamente se o IP de origem pertence
    à faixa oficial autorizada (`189.9.61.23/32`).
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    source_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else (request.client.host if request.client else "")
    )
    ambiente = request.headers.get("X-RFB-Ambiente", "PRODUCAO")

    if not validate_rfb_webhook_ip(source_ip, ambiente=ambiente):
        repo.log_audit(
            user_email="webhook@rfb",
            user_role="EXTERNO",
            action="WEBHOOK_IP_BLOQUEADO",
            target_entity="webhook",
            details=f"Tentativa de POST no webhook rejeitada por IP fora da Allowlist da RFB: {source_ip}",
            ip_address=source_ip or "desconhecido",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP de origem não pertence à faixa oficial da Receita Federal (189.9.61.23/32).",
        )

    payload = await request.json()
    tiquete = payload.get("tiqueteSolicitacao", "N/A")
    situacao = payload.get("situacao", payload.get("codigoErro", "DESCONHECIDO"))

    repo.log_audit(
        user_email="webhook@rfb.gov.br",
        user_role="RFB_CALLBACK",
        action="WEBHOOK_RECEBIDO",
        target_entity=f"tiquete:{tiquete}",
        details=f"Notificação oficial recebida via Webhook. Situação: {situacao}",
        ip_address=source_ip,
    )
    return {"status": "recebido", "tiqueteSolicitacao": tiquete, "situacao": situacao}
