import re

from fastapi import BackgroundTasks, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.constants import AnsiColor
from app.core.database import SessionLocal
from app.model import AdminTable
from app.schema import GlobalResponse
from services.auth.user_verification import UserVerificationService



ORIGIN_REGEX = re.compile(
    r"^https://([a-zA-Z0-9-]+\.)*dting\.online$"
)


class AdminAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        protected_prefixes: list[str] | None = None,
        public_paths: list[str] | None = None,
        dev_mode: bool = False
    ):
        super().__init__(app)
        self.protected_prefixes = protected_prefixes or []
        self.public_paths = public_paths or []
        self.dev_mode = dev_mode

    async def dispatch(self, request: Request, call_next):
        client_type = request.headers.get("X-Client-Type")
        ua = request.headers.get("user-agent", "").lower()

        if not client_type:
            if "okhttp" in ua or "dart" in ua:
                client_type = "android"
            elif "postman" in ua:
                client_type = "postman"
            elif "curl" in ua:
                client_type = "curl"
            elif "python" in ua:
                client_type = "python"
            else:
                client_type = "web"

        request.state.client_type = client_type

        if (
            request.method == "OPTIONS"
            or self._is_public_path(request.url.path)
            or not self._is_protected_path(request.url.path)
        ):
            return await call_next(request)

        access_token: str | None = None
        authorization = request.headers.get("Authorization")

        if authorization and authorization.lower().startswith("bearer "):
            access_token = authorization.split(" ", 1)[1].strip()

        if not access_token and client_type == "web":
            access_token = request.cookies.get("admin_access_token")

        if not access_token and self.dev_mode:
            access_token = request.query_params.get("admin_token")

        if not access_token:
            print(f"{AnsiColor.BLUE}INFO:{AnsiColor.RESET}     Missing admin token. client={client_type} path={request.url.path}")
            return self._unauthorized(request=request, message="Missing admin authentication token")

        db: Session = SessionLocal()
        background_tasks = BackgroundTasks()

        try:
            verifier = UserVerificationService(
                db=db,
                background_tasks=background_tasks,
                request=request,
                authorization=f"Bearer {access_token}"
            )
            admin: AdminTable = verifier.verify_admin_authorization()
            request.state.current_admin = admin

        except Exception as exc:
            status_code = getattr(exc, "status_code", status.HTTP_401_UNAUTHORIZED)
            detail = getattr(exc, "detail", "Invalid or Expired Admin Token")
            return self._unauthorized(request=request, message=detail, status_code=status_code)

        finally:
            pass
            # db.close()

        return await call_next(request)

    def _is_protected_path(self, path: str) -> bool:
        return any(path == prefix or path.startswith(f"{prefix}/") for prefix in self.protected_prefixes)

    def _is_public_path(self, path: str) -> bool:
        return path in self.public_paths

    def _unauthorized(self, request: Request, message: str, status_code: int = 401):
        response = GlobalResponse(
            status_code=status_code,
            success=False,
            action="unauthorized",
            message=message,
            data={}
        )

        resp = JSONResponse(
            status_code=status_code,
            content=response.model_dump()
        )

        origin = request.headers.get("origin")

        if origin and ORIGIN_REGEX.fullmatch(origin):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Vary"] = "Origin"

        return resp