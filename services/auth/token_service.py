import uuid
from fastapi import HTTPException, Request, BackgroundTasks, Response, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import JWTError, jwt

from app.constants import ENV, String, AnsiColor
from app.schema import RefreshAccessTokenRequest, GlobalResponse, FCMTokenRequest
from app.model import SessionTable, UserTable
from app.utils import Hashing


class TokenGenerators:
    def __init__(self):
        with open(ENV.PRIVATE_KEY_PATH, "r") as f:
            self.PRIVATE_KEY = f.read()

        with open(ENV.PUBLIC_KEY_PATH, "r") as f:
            self.PUBLIC_KEY = f.read()

        self.ALGORITHM = "RS256"

    def _create_token(
        self,
        payload: dict,
        expire_day: float = 0,
        expire_min: float = 0
    ) -> tuple[str, str]:
        to_encode = payload.copy()
        expire = datetime.utcnow() + timedelta(days=expire_day, minutes=expire_min)
        jti = str(uuid.uuid4())   # unique token id - revoke/rotation track korar jonno

        to_encode.update({
            "exp": expire,
            "jti": jti,
        })

        token = jwt.encode(to_encode, self.PRIVATE_KEY, algorithm=self.ALGORITHM)

        return token, jti

    def _decode_token(
        self,
        token: str,
        audience: str | list[str] | None = None,
        issuer: str | None = None
    ):
        try:
            if not token:
                return None
            
            decode_kwargs = {
                "key": self.PUBLIC_KEY,
                "algorithms": [self.ALGORITHM],
                "options": {
                    "verify_aud": False
                }
            }
            
            if issuer is not None:
                decode_kwargs["issuer"] = issuer

            if audience is not None and isinstance(audience, list) and len(audience) > 1:
                pass

            elif audience is not None:
                decode_kwargs["audience"] = audience

            # print(type(audience))
            # print(audience)
            # print(decode_kwargs)
            payload = jwt.decode(token, **decode_kwargs)
            
            if audience is not None and isinstance(audience, list) and len(audience) > 1:
                token_aud = payload.get("aud", [])

                if isinstance(token_aud, str):
                    token_aud = [token_aud]

                expected_audiences = set(audience)
                token_audiences = set(token_aud)

                if not expected_audiences.intersection(token_audiences):
                    raise JWTError("Invalid audience")

            return payload

        except JWTError as j:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     JWT Error: {j}")
            return None



class TokenService(TokenGenerators):
    def __init__(
        self,
        db: Session,
        background_tasks: BackgroundTasks,
        request: Request,
        authorization: str
    ):
        super().__init__()
        self.db = db
        self.background_tasks = background_tasks
        self.request = request
        self.authorization = authorization

    def create_access_token(self, user_id: str, device_id: str, device_uuid: str) -> str:
        payload = {
            "token_type": "access",
            "user_id": user_id,
            "device_id": device_id,
            "device_uuid": device_uuid,
            "iss": f"api.auth{ENV.MAIN_DOMAIN}",
            "aud": ENV.MAIN_DOMAIN,
            "iat": datetime.utcnow(),
        }
        token, jti = self._create_token(
            payload=payload,
            expire_min=ENV.ACCESS_EXPIRE_MINUTES
        )

        return token

    def create_refresh_token(self, user_id: str, device_id: str, device_uuid: str) -> str:
        payload = {
            "token_type": "refresh",
            "user_id": user_id,
            "device_id": device_id,
            "device_uuid": device_uuid,
            "iss": f"api.auth{ENV.MAIN_DOMAIN}",
            "aud": f"api.auth{ENV.MAIN_DOMAIN}",
            "iat": datetime.utcnow(),
        }
        token, jti = self._create_token(
            payload=payload,
            expire_day=ENV.REFRESH_EXPIRE_DAYS
        )

        return token

    def verify_access_token(self, token: str) -> dict | None:
        if not token:
            return None
        
        payload = self._decode_token(
            token,
            audience=ENV.MAIN_DOMAIN,
            issuer=f"api.auth{ENV.MAIN_DOMAIN}",
        )
        
        if payload and payload.get("token_type") == "access":
            return payload
        
        return None

    def verify_refresh_token(self, token: str) -> dict | None:
        payload = self._decode_token(
            token,
            audience=f"api.auth{ENV.MAIN_DOMAIN}",
            issuer=f"api.auth{ENV.MAIN_DOMAIN}" if ENV.DEBUG else None,
        )

        if not payload or payload.get("token_type") != "refresh":
            return None

        return payload

    # Get a New Access Token Using Refresh Token
    def refresh_access_token(
        self,
        payload: RefreshAccessTokenRequest,
        response: Response | None = None
    ) -> GlobalResponse:
        try:
            # Step 1: Extract data from payload
            refresh_token = self.authorization

            if not refresh_token and payload is not None:
                refresh_token = payload.refresh_token

            if not refresh_token and self.request.cookies.get("refresh_token") is not None:
                refresh_token = self.request.cookies.get("refresh_token")
            
            if refresh_token and refresh_token.lower().startswith("bearer "):
                refresh_token = refresh_token.split(" ", 1)[1].strip()
            
            if not refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_OR_EXPIRED_TOKEN
                )

            # Step 2: Decode and validate refresh token
            token_payload: dict = self.verify_refresh_token(refresh_token)

            if token_payload is None:
                raise HTTPException(
                    status_code=401,
                    detail="Refresh Token Expired"
                )
            

            user_id = payload.user_id or token_payload.get("user_id")
            device_id = payload.device_id or token_payload.get("device_id")
            device_uuid = payload.device_uuid or token_payload.get("device_uuid")
            
            if not user_id or not device_id or not device_uuid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_OR_EXPIRED_TOKEN
                )

            if token_payload.get("user_id") != user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User ID mismatch"
                )

            # Step 3: Verify session
            session: SessionTable = self.db.query(SessionTable).filter(
                SessionTable.user_id == user_id,
                SessionTable.device_id == device_id,
                SessionTable.device_uuid == device_uuid
            ).first()

            if (not session):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=String.SESSION_NOT_FOUND
                )

            if (not session.is_login or not session.otp_verified):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.USER_NOT_LOGIN
                )


            # Step 4: Generate new access token
            access_token = self.create_access_token(
                user_id=user_id,
                device_id=device_id,
                device_uuid=device_uuid
            )


            # Step 5: Update session with new access token hash
            session: SessionTable = self.db.query(SessionTable).filter(
                SessionTable.user_id == user_id,
                SessionTable.device_id == device_id,
                SessionTable.device_uuid == device_uuid
            ).first()

            if session:
                session.access_token_hash = Hashing.create_hash(access_token)
                self.db.commit()
                self.db.refresh(session)

            if response is not None:
                response.set_cookie(
                    key="access_token",
                    value=access_token,
                    httponly=True,
                    secure=False,
                    samesite="lax",
                    domain=None if ENV.DEBUG else f".{ENV.MAIN_DOMAIN}",
                    max_age=ENV.ACCESS_EXPIRE_MINUTES * 60,
                    path="/"
                )


            # Return Response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="refresh_access_token",
                message="Access token refreshed successfully",
                data={
                    "access_token": access_token
                },
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)
    
    # FCM token receive from user
    def receive_fcm_token(self, payload: FCMTokenRequest) -> GlobalResponse:
        try:
            # Step 1: Extract data from payload
            user_id: str = payload.user_id
            access_token: str = payload.access_token
            device_id: str = payload.device_id
            device_uuid: str = payload.device_uuid
            fcm_token: str = payload.fcm_token
            

            # Step 1: Get current user
            user: UserTable = self.request.state.current_user


            # Step 3: Update current session FCM token
            user_sessions: list[SessionTable] = user.sessions
            current_session = next(
                (
                    session for session in user_sessions
                    if session.device_id == device_id
                    and session.device_uuid == device_uuid
                    and session.is_login
                ),
                None
            )

            if not current_session:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.SESSION_NOT_FOUND
                )

            current_session.fcm_token = fcm_token
            self.db.commit()
            self.db.refresh(current_session)
            

            # Step 4: Return Response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="receive_fcm_token",
                message="FCM token received successfully",
                data={},
                next_step={}
            )
        
        except HTTPException:
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)






# ==============================================================================
# ==============================================================================
