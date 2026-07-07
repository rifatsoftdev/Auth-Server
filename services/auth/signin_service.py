import random
import string

from datetime import timedelta

from fastapi import BackgroundTasks, HTTPException, Request, Response, status, Header
from sqlalchemy.orm import Session

from app.constants import AnsiColor, String, ENV
from app.enums import NotificationType
from app.model import DeletedUserTable, NotificationTable, SessionTable, SettingsTable, TwoFactorTable, UserTable
from app.schema import (
    GlobalResponse, CancelDeleteAccountRequest, DeleteAccountRequest, LoginRequest,
    LogoutRequest, LogoutAllRequest
)
from app.utils import Hashing, Helpers

from services.auth.repository import Repository
from services.auth.token_service import TokenService
from services.auth.signup_service import RegistrationService

from services.notification.notification_services import (
    NotificationServices, NotificationData, NotificationEvent
)


class SigninService(TokenService, Repository):
    def __init__(
        self,
        db: Session,
        background_tasks: BackgroundTasks,
        request: Request,
        authorization: str = Header(None)
    ):
        super().__init__(db=db, background_tasks=background_tasks, request=request, authorization=authorization)

    def _masked_tfa_destination(self, method_type: str, method: TwoFactorTable, user: UserTable) -> str | None:
        delivery_address = method.delivery_address

        if method_type == "email":
            return self._mask_email(delivery_address or user.email_address)

        if method_type == "sms":
            phone_number = delivery_address or f"{user.country_code or ''}{user.phone_number or ''}" or None
            return self._mask_phone(phone_number)

        return None

    @staticmethod
    def _normalize_tfa_method(method_type) -> str:
        return method_type.value if hasattr(method_type, "value") else str(method_type).lower()


    # This will log in the user and create a session. If 2FA is enabled, it will return a response indicating that 2FA verification is required. If 2FA is not enabled, it will return the access token and refresh token.
    def signin(
        self, 
        payload: LoginRequest,
        response: Response
    ) -> GlobalResponse:
        try:
            # Step 0: Get data from request
            email_address: str = payload.email_address
            phone_number: str = payload.phone_number
            country_code: str = payload.country_code
            user_password: str = payload.user_password
            device_id: str = payload.device_id
            device_uuid: str = payload.device_uuid
            
            ip: str = self.request.client.host if self.request and self.request.client else None
            client_type = self.request.headers.get("X-Client-Type", "").lower()

            # Step 1: Find user by email or phone
            user: UserTable = self._check_user_already_exists(
                email=email_address,
                phone=phone_number,
                country_code=country_code
            )
            
            if not user:
                return GlobalResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    success=False,
                    message=String.USER_NOT_FOUND,
                    action="user_not_found",
                    data={},
                    next_step={
                        "endpoint": "/auth/register",
                        "method": "POST",
                        "payload": {
                            "email_address": email_address,
                            "phone_number": phone_number,
                            "country_code": country_code,
                            "user_password": user_password,
                            "device_id": device_id,
                            "device_uuid": device_uuid
                        }
                    }
                )

            settings: SettingsTable = user.settings

            if not settings:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=String.SETTINGS_NOT_FOUND
                )
            
            if settings.account_deactivated:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.ACCOUNT_LOCKED
                )


            # Step 2: Check if password is set
            if not user.password_hash:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=String.PASSWORD_NOT_SET
                )


            # Step 3: Verify password
            if (not Hashing.verify_password(user_password, user.password_hash)):
                raise HTTPException(
                    status_code=401,
                    detail=String.INVALID_PASSWORD
                )


            # Step 4: Check email verification
            if (not user.email_verified):
                registration_service = RegistrationService(
                    db=self.db,
                    background_tasks=self.background_tasks,
                    request=self.request,
                    authorization=self.authorization
                )

                response: GlobalResponse = registration_service.email_verification_required_response(
                    user=user,
                    device_id=device_id,
                    device_uuid=device_uuid
                )

                self.db.commit()

                return response

            
            access_token = None
            refresh_token = None


            # Step 5: Check 2FA status and methods
            enabled_tfa_methods = self.db.query(TwoFactorTable).filter(
                TwoFactorTable.user_id == user.user_id,
                TwoFactorTable.is_enabled == True
            ).order_by(
                TwoFactorTable.is_primary.desc(),
                TwoFactorTable.created_at.asc()
            ).all()

            two_factor_method_names = [
                self._normalize_tfa_method(method.method_type)
                for method in enabled_tfa_methods
            ]
            two_factor_methods = [
                {
                    "method": method_type,
                    "delivery_address": self._masked_tfa_destination(method_type, method, user),
                    "is_primary": method.is_primary
                }
                for method, method_type in zip(enabled_tfa_methods, two_factor_method_names)
            ]
            is_2fa_required = bool(two_factor_method_names)
            
            if not is_2fa_required:
                access_token = self.create_access_token(
                    user_id=user.user_id,
                    device_id=device_id,
                    device_uuid=device_uuid
                )

                refresh_token = self.create_refresh_token(
                    user_id=user.user_id,
                    device_id=device_id,
                    device_uuid=device_uuid
                )
            

            # Step 6: Create or Update Session
            session = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.device_id == device_id,
                SessionTable.device_uuid == device_uuid
            ).first()
            
            if session:
                session.access_token_hash = Hashing.create_hash(access_token) if access_token else None
                session.refresh_token_hash = Hashing.create_hash(refresh_token) if refresh_token else None
                session.last_ip_address = ip
                session.login_at = Helpers.utc6dhaka()
                session.logout_at = None
                session.is_login = not is_2fa_required
                session.otp_verified = not is_2fa_required
            else:
                session = SessionTable(
                    user_id=user.user_id,
                    fcm_token=None,
                    access_token_hash=Hashing.create_hash(access_token) if access_token else None,
                    refresh_token_hash=Hashing.create_hash(refresh_token) if refresh_token else None,
                    device_uuid=device_uuid,
                    device_id=device_id,
                    login_at=Helpers.utc6dhaka(),
                    last_ip_address=ip,
                    is_login=not is_2fa_required,
                    otp_verified=not is_2fa_required
                )
                self.db.add(session)
                self.db.flush()

            
            # Step 7: Create notification record
            new_notification = NotificationTable(
                target_id=user.user_id,
                type=NotificationType.ALERT,
                title="New Login Detected",
                body=f"Your account was logged in from IP {ip} on {Helpers.utc6dhaka()}. If this wasn’t you, change your password immediately."
            )
            self.db.add(new_notification)
            self.db.flush()


            # Step 8: Send notification alerts
            notification_services = NotificationServices(
                db=self.db,
                background_tasks=self.background_tasks,
                request=self.request,
                authorization=self.authorization
            )

            notification_services.send_notification(
                data=NotificationData(
                    user_id=user.user_id,
                    email_address=user.email_address,
                    event=NotificationEvent.GENERAL_NOTIFICATION,
                    context={
                        "name": user.full_name or user.username or "User",
                        "title": "New Login Detected",
                        "message": f"Your account was logged in from IP {ip}. If this wasn't you, please secure your account."
                    },
                    push=True,
                    email=True
                )
            )
            

            # Step 9: Finalize database changes
            self.db.commit()
            # self.db.refresh(session)
            self.db.refresh(new_notification)
            

            # Step 10: Handle 2FA or direct login response
            if is_2fa_required:
                request_token, _ = self._create_token(
                    expire_min=5,
                    payload={
                        "token_type": "otp_token",
                        "user_id": user.user_id,
                        "device_id": device_id,
                        "device_uuid": device_uuid,
                        "type": "2fa_request"
                    }
                )
                
                return GlobalResponse(
                    status_code=status.HTTP_200_OK,
                    success=True,
                    action="2fa_verification_required",
                    message="Two-factor verification required",
                    data={
                        "requires_2fa": True,
                        "request_token": request_token, 
                        "otp_token": request_token,
                        "two_factor_methods": two_factor_methods,
                        "user_id": user.user_id,
                        "device_id": device_id,
                        "device_uuid": device_uuid
                    },
                    next_step={
                        "endpoint": "/auth/verify-otp",
                        "method": "POST",
                        "payload": {
                            "otp_token": "request_token",
                            "otp": "otp",
                            "method": "totp/sms/email",
                            "purpose": "login",
                            "device_id": "device_id",
                            "device_uuid": "device_uuid"
                        }
                    }
                )

            print(f"{AnsiColor.BLUE}INFO:{AnsiColor.RESET}     Client type: {client_type}")
            if True or client_type == "web":
                print(f"{AnsiColor.BLUE}INFO:{AnsiColor.RESET}     Setting cookies for web client. access_token={access_token[0:4]}.., refresh_token={refresh_token[0:4]}..")
                response.set_cookie(
                    key="access_token",
                    value=access_token,
                    httponly=True,
                    secure=True,  # production হলে True + HTTPS
                    samesite="lax",
                    domain=ENV.MAIN_DOMAIN,
                    max_age=ENV.ACCESS_EXPIRE_MINUTES * 60,
                    path="/"
                )
                response.set_cookie(
                    key="refresh_token",
                    value=refresh_token,
                    httponly=True,
                    secure=True,
                    samesite="strict",
                    domain=ENV.MAIN_DOMAIN,
                    max_age=ENV.REFRESH_EXPIRE_DAYS * 86400, # fix: din -> second e convert kora (1 din = 86400 sec)
                    path="/auth/refresh-access-token"
                )

                response.set_cookie(
                    key="user_id",
                    value=user.user_id,
                    httponly=False,      # JavaScript access করতে পারবে
                    secure=True,
                    samesite="lax",
                    domain=ENV.MAIN_DOMAIN,
                    path="/",
                    max_age=ENV.REFRESH_EXPIRE_DAYS * 86400
                )

                response.set_cookie(
                    key="device_id",
                    value=device_id,
                    httponly=False,
                    secure=True,
                    samesite="lax",
                    domain=ENV.MAIN_DOMAIN,
                    path="/",
                    max_age=ENV.REFRESH_EXPIRE_DAYS * 86400
                )

                response.set_cookie(
                    key="device_uuid",
                    value=device_uuid,
                    httponly=False,
                    secure=True,
                    samesite="lax",
                    domain=ENV.MAIN_DOMAIN,
                    path="/",
                    max_age=ENV.REFRESH_EXPIRE_DAYS * 86400
                )

                # print(response.headers)
                return GlobalResponse(
                    status_code=status.HTTP_200_OK,
                    success=True,
                    action="login",
                    message="Login successful",
                    data={
                        "requires_2fa": False,
                        "user_id": user.user_id,
                        "device_id": device_id,
                        "device_uuid": device_uuid,
                        "token_type": "Bearer",
                        "expires_in": ENV.ACCESS_EXPIRE_MINUTES * 60,   # consistency: ekhane o second e rakha better
                        "email_address": user.email_address,
                        "phone_number": f"{user.country_code or ''}{user.phone_number or ''}" or None
                    },
                    next_step={}
                )

            # Step 11: Return Direct Login Response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="login",
                message="Login successful",
                data={
                    "requires_2fa": False,
                    "user_id": user.user_id,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": ENV.ACCESS_EXPIRE_MINUTES,
                    "email_address": user.email_address,
                    "phone_number": f"{user.country_code or ''}{user.phone_number or ''}" or None
                },
                next_step={}
            )
        
        except HTTPException:
            raise
        
        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


# This will log out the user from the current device only
    def logout(
        self, 
        payload: LogoutRequest
    ) -> GlobalResponse:
        try:
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user


            # Step 2: Find and update the current session using token from cookie
            access_token = self.request.cookies.get("access_token")
            if access_token:
                token_hash = Hashing.create_hash(access_token)
                session = self.db.query(SessionTable).filter(
                    SessionTable.access_token_hash == token_hash,
                    SessionTable.is_login == True
                ).first()
            else:
                # Fallback: find any active session for user
                session = self.db.query(SessionTable).filter(
                    SessionTable.user_id == user.user_id,
                    SessionTable.is_login == True
                ).first()

            if not session:
                raise HTTPException(
                    status_code=404,
                    detail=String.SESSION_NOT_FOUND
                )
            
            session.access_token_hash = None
            session.refresh_token_hash = None
            session.is_login = False
            session.fcm_token = None
            session.logout_at = Helpers.utc6dhaka()

            # Step 3: Finalize database changes
            self.db.commit()
            self.db.refresh(session)


            # Return Response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="logout",
                message=String.LOGOUT_SUCCESSFUL,
                data={},
                next_step={}
            )
        
        except HTTPException:
            raise
        
        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # This will log out all sessions of the user across all devices
    def logout_all(self, payload: LogoutAllRequest):
        try:
            # Step 1: Extract data from payload
            user_id: str = payload.user_id
            access_token: str = payload.access_token
            android_id: str = payload.device_id
            android_uuid: str = payload.device_uuid


            # Step 1: Get current user
            user: UserTable = self.request.state.current_user


            # Step 3: Find and update all active sessions
            sessions = self.db.query(SessionTable).filter(
                SessionTable.user_id == user_id,
                SessionTable.is_login == True
            ).all()

            for session in sessions:
                session.is_login = False
                session.fcm_token = None
                session.access_token_hash = None
                session.refresh_token_hash = None
                session.logout_at = Helpers.utc6dhaka()


            # Step 4: Finalize database changes
            self.db.commit()


            # Step 5: Return Response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="logout_all",
                message="All sessions logged out successfully",
                data={},
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)






# ==============================================================================
# ==============================================================================
