import os

from pathlib import Path

from fastapi import FastAPI, Header, Request, HTTPException, status
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.constants import ENV, AnsiColor
from app.schema.global_schema import GlobalResponse
from app.middleware.user_auth_middleware import AuthMiddleware
from app.middleware.admin_auth_middleware import AdminAuthMiddleware
from sqlalchemy.orm import Session
from services.auth.user_verification import UserVerificationService

from admin.router.access_router import admin_access_router
from admin.router.auth_router import admin_auth_router
from admin.router.server_router import server_router

from app.router.auth_router import auth_router
from app.router.country_router import country_router
from app.router.dev_router import dev_router
from app.router.feedback_router import feedback_router
from app.router.history_router import history_router
from app.router.notify_router import notyfy_router
from app.router.offer_router import offer_router
from app.router.seo_router import seo_router
from app.router.service_router import service_router
# from app.router.template_router import template_router
from app.router.settings_router import settings_router
from app.router.tfa_router import tfa_router
from app.router.me_router import me_router

from services.setup.setup_services import SetupServices
from services.notification.websocket_push_manager import NotifyWebSocket
import app.core.firebase




# create FastAPI
app = FastAPI(
    title="DTing Server",
    description="DTIng server authentication system.",
    version=ENV.VERSION,
)


# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https://([a-zA-Z0-9-]+\.)*dting\.online$",
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


# Configure authentication middleware
app.add_middleware(
    AdminAuthMiddleware,
    public_paths=[
        "/admin/login",
        "/admin/refresh-access-token"
    ],
    protected_prefixes=[
        "/admin",
    ]
)

app.add_middleware(
    AuthMiddleware,
    public_paths=[
        "/health",
        "/country/counties",
        "/login",
        "/admin/login",
        "/auth/refresh-access-token",
        "/auth/new-access-token",
        "/admin/refresh-access-token"
    ],
    protected_prefixes=[
        "/bank",
        "/bill",
        "/country",
        "/dev",
        "/donation",
        "/feedback",
        "/history",
        "/me",
        "/offer",
        "/qr",
        "/recharge",
        "/tfa",
        "/user",
        "/wallet",
    ]
)


# Configure static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
TMP_DIR = Path("uploads/tmp")


# Startup event
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        setupServices = SetupServices(
            db=db,
            background_tasks=None,
            request=None,
            authorization=None
        )

    finally:
        db.close()


# Shutdown event
@app.on_event("shutdown")
def shutdown_event():
    exit_code = 1
    # exit_code = os.system("find . -type d -name \"__pycache__\" -exec rm -rf {} +")
    print(f"{AnsiColor.BLUE}INFO:{AnsiColor.RESET}     Shutting down application... Cleaning up resources exit code {exit_code}")


# Custom exception handlers
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    message = exc.detail if getattr(exc, "detail", None) else "Not Found"

    return HTMLResponse(
        content=templates.get_template("server/404.html").render(request=request, message=message),
        status_code=status.HTTP_404_NOT_FOUND
    )


# Custom exception handlers
@app.exception_handler(Exception)
async def server_exception_handler(request: Request, exc: Exception):
    return HTMLResponse(
        content=templates.get_template("server/500.html").render(request=request, message=str(exc)),
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )




# ==============================================================================

@app.get("/")
async def root(
    request: Request,
    authorization: str = Header(None)
):
    return RedirectResponse("/health")



# ==============================================================================

@app.get("/health")
async def root(
    request: Request,
    authorization: str = Header(None)
):
    return GlobalResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        action="welcome",
        message="Welcome to DTing Server.",
        data={
            "app": "DTing",
            "version": ENV.VERSION,
            "description": "DTIng server authentication system."
        },
        next_step={}
    )


# ==============================================================================

@app.get("/.well-known/public.pem")
async def public_key(request: Request):
    public_key_path = ENV.PUBLIC_KEY_PATH

    if not os.path.exists(public_key_path):
        print(1)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Public key not found"
        )
    
    return FileResponse(public_key_path)
    


# ==============================================================================

@app.get("/test")
async def root(
    request: Request,
    authorization: str = Header(None)
):
    from services.notification.email_manager import EmailManager

    emailManager = EmailManager()
    emailManager.send_email(
        email_address="example@gmail.com",
        subject="Test Email",
        body="This is a test email from DTing API"
    )

    return {}
    user_id="USRF35338A5F7704BF0A0990B8A341D023D"

    notifyWebSocket = NotifyWebSocket()
    # print(await notifyWebSocket._is_online_user(user_id))

    await notifyWebSocket.send_notification(
        user_id="USRF35338A5F7704BF0A0990B8A341D023D",
        title="Test Notification",
        body="This is a test notification from DTing API",
        payload = {
            "notification_id": "uuid-123",
            "type": "test",
            "title": "Test Notification",
            "body": "This is a test notification from PocketPay API",

            "user_id": "USRF35338A5F7704BF0A0990B8A341D023D",

            "priority": "normal",
            "created_at": "2024-06-30T12:00:00Z",

            "action": {
                "type": "open_url",
                "target": "https://example.com/notification-action"
            },

            "deep_link": "pocketpay://test",

            "image": "https://example.com/notification-image.png",

            "category": "test",

            "meta": {
                "timestamp": "2024-06-30T12:00:00Z"
            }
        }
    )

    return {}




@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")




# Include routers
app.include_router(admin_access_router, prefix="/admin", tags=["Admin Management"])
app.include_router(admin_auth_router, prefix="/admin", tags=["Admin Management"])
app.include_router(server_router, prefix="/admin/config", tags=["Admin Configuration"])

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(country_router, prefix="/country", tags=["Countries"])
app.include_router(dev_router, prefix="/dev", tags=["Development"])
app.include_router(feedback_router, prefix="/feedback", tags=["Feedback"])
app.include_router(history_router, prefix="/history", tags=["Transaction History"])
app.include_router(notyfy_router, prefix="/ws", tags=["Notifications"])
app.include_router(offer_router, prefix="/offer", tags=["Offers"])
app.include_router(seo_router)
app.include_router(service_router, prefix="/service", tags=["Services"])
# app.include_router(template_router, prefix="", tags=["Templates"])
app.include_router(settings_router, prefix="/admin/settings", tags=["Admin Settings"])
app.include_router(tfa_router, prefix="/tfa", tags=["Two-Factor Authentication"])
app.include_router(me_router, prefix="/me", tags=["User Data"])




# ==============================================================================
# ==============================================================================
