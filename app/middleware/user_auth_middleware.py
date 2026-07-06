import re

from fastapi import status, Request, BackgroundTasks, Header, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.constants import AnsiColor
from app.model import UserTable
from app.schema import GlobalResponse
from services.auth.user_verification import UserVerificationService



ORIGIN_REGEX = re.compile(
    r"^https://([a-zA-Z0-9-]+\.)*dting\.online$"
)



class UserAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        protected_prefixes: list[str] | None = None,
        public_paths: list[str] | None = None,
        dev_mode: bool = False # Dev er jonno extra flag
    ):
        super().__init__(app)
        self.protected_prefixes = protected_prefixes or []
        self.public_paths = public_paths or []
        self.dev_mode = dev_mode

    async def dispatch(self, request: Request, call_next):
        # Step 1: Client type detect - just for logging/analytics
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

        # Step 2: Public route ba OPTIONS hoile skip
        if (request.method == "OPTIONS"
            or self._is_public_path(request.url.path)
            or not self._is_protected_path(request.url.path)
        ):
            return await call_next(request)
        

        # Step 3: Token ber koro - Client type er upor depend na kore
        access_token: str | None = None

        # Priority 1: Authorization header - Postman/Python/Android/Web shobai dite pare
        authorization = request.headers.get("Authorization")

        if authorization and authorization.lower().startswith("bearer "):
            access_token = authorization.split(" ", 1)[1].strip()


        # Priority 2: Cookie - shudhu web er jonno fallback
        if not access_token and client_type == "web":
            access_token = request.cookies.get("access_token")

        # Dev mode e aro flexible korte paro
        if not access_token and self.dev_mode:
            # Query param diyeo token nite paro dev e
            access_token = request.query_params.get("token")

        if not access_token:
            print(f"{AnsiColor.BLUE}INFO:{AnsiColor.RESET}     Missing token. client={client_type} path={request.url.path}")
            return self._unauthorized(request, "Missing authentication token")

        # 4. Token verify koro
        db: Session = SessionLocal()
        background_tasks: BackgroundTasks = BackgroundTasks()

        try:
            userVerificationService = UserVerificationService(
                db=db,
                background_tasks=background_tasks,
                request=request,
                authorization=f"Bearer {access_token}"
            )
            user: UserTable = userVerificationService.verify_user_authorization()

            request.state.current_user = user
            # print(user)
            
        except Exception as exc:
            status_code = getattr(exc, "status_code", status.HTTP_401_UNAUTHORIZED)
            detail = getattr(exc, "detail", "Invalid or Expired Token")
            return self._unauthorized(request, detail, status_code=status_code)
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