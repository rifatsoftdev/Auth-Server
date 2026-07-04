from datetime import timedelta

from fastapi import BackgroundTasks, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.constants import AnsiColor, String, ENV
from app.enums import NotificationType
from app.model import DeletedUserTable, NotificationTable, SessionTable, SettingsTable, UserTable
from app.schema import (
    GlobalResponse, CancelDeleteAccountRequest, DeleteAccountRequest,
    FCMTokenRequest, SetUsernameRequest, RefreshAccessTokenRequest
)
from app.utils import Hashing, Helpers

from services.auth.otp_service import OTPService

from services.auth.repository import Repository
from services.auth.token_service import TokenGenerators
from services.auth.signup_service import RegistrationService

from services.notification.notification_services import NotificationServices, NotificationData, NotificationEvent
from services.auth.signin_service import SigninService



class AccountServices(OTPService, SigninService):
    def __init__(
        self,
        db: Session,
        background_tasks: BackgroundTasks,
        request: Request,
        authorization: str
    ):
        OTPService.__init__(
            self,
            db=db,
            background_tasks=background_tasks,
            request=request,
            authorization=authorization
        )
        Repository.__init__(self, db)
        SigninService.__init__(
            self,
            db=db,
            background_tasks=background_tasks,
            request=request,
            authorization=authorization
        )

    @staticmethod
    def _mask_email(email_address: str | None) -> str | None:
        if not email_address or "@" not in email_address:
            return None

        local_part, domain = email_address.split("@", 1)
        if not local_part:
            return f"***@{domain}"

        visible_count = 2 if len(local_part) > 2 else 1
        return f"{local_part[:visible_count]}***@{domain}"

    @staticmethod
    def _mask_phone(phone_number: str | None) -> str | None:
        if not phone_number:
            return None

        if len(phone_number) <= 4:
            return "*" * len(phone_number)

        visible_prefix = min(4, len(phone_number) - 2)
        return f"{phone_number[:visible_prefix]}{'*' * (len(phone_number) - visible_prefix - 2)}{phone_number[-2:]}"


    # username Set or Change
    def set_username(self, payload: SetUsernameRequest) -> GlobalResponse:
        try:
            # Step 1: Extract data from payload
            user_id: str = payload.user_id
            access_token: str = payload.access_token
            android_id: str = payload.device_id
            android_uuid: str = payload.device_uuid
            username: str = payload.username.strip()

            
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user


            # Step 3: Check if username is already taken by another user
            existing_username = self.db.query(UserTable).filter(
                UserTable.username == username,
                UserTable.user_id != user.user_id
            ).first()

            if existing_username:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username already taken"
                )


            # Step 4: Update username
            old_username = user.username
            user.username = username
            

            # Step 5: Notify user
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
                        "title": "Username Updated",
                        "message": f"Your username has been successfully changed from @{old_username} to @{username}."
                    },
                    push=True,
                    email=True
                )
            )
            

            # Step 6: Return Response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="set_username",
                message="Username set successfully",
                data={
                    "username": user.username
                },
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


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
            token_payload: dict = self._decode_token(refresh_token)

            if token_payload == None:
                raise HTTPException(
                    status_code=401,
                    detail="Refresh Token Expired"
                )
            
            if token_payload.get("token_type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Token"
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
            access_token, _ = self._create_token(
                expire_min=ENV.ACCESS_EXPIRE,
                payload={
                    "token_type": String.ACCESS_TOKEN,
                    "user_id": user_id,
                    "device_id": device_id,
                    "device_uuid": device_uuid,
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    "aud": ENV.ALLOWED_AUDIENCES,
                }
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
                    max_age=ENV.ACCESS_EXPIRE * 60,
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


    # User Account Delete Request
    def delete_account(self, payload: DeleteAccountRequest) -> GlobalResponse:
        try:
            # Step 1: Extract data from payload
            user_password: str = payload.user_password
            reason: str = payload.reason
            ip: str = self.request.client.host


            # Step 1: Get current user
            user: UserTable = self.request.state.current_user


            # Step 3: check existing delete request
            existing_request = self.db.query(DeletedUserTable).filter(
                DeletedUserTable.user_id == user.user_id,
                DeletedUserTable.is_processed == False
            ).first()

            if existing_request:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Delete request already submitted"
                )

            
            # Step 4: Verify password
            if not Hashing.verify_hash(user_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password"
                )
            

            # Step 5: Schedule deletion and update account status 
            scheduled_delete_at = Helpers.utc6dhaka() + timedelta(days=7)

            delete_record = DeletedUserTable(
                user_id=user.user_id,
                full_name=user.full_name,
                email_address=user.email_address,
                country_code=user.country_code,
                phone_number=user.phone_number,
                reason=reason,
                requested_at=Helpers.utc6dhaka(),
                scheduled_delete_at=scheduled_delete_at,
                is_processed=False
            )
            self.db.add(delete_record)

            settings = self.db.query(SettingsTable).filter(
                SettingsTable.user_id == user.user_id
            ).first()

            if settings:
                settings.account_deactivated = True


            # Step 6: Create notification record and send alerts
            notification_body = f"We received a delete account request from IP {ip}. Your account will be removed after review."
            new_notification = NotificationTable(
                target_id=user.user_id,
                type=NotificationType.ALERT,
                title="Delete Account Requested",
                body=notification_body
            )
            self.db.add(new_notification)
            self.db.flush()

            active_session = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.is_login == True,
                SessionTable.fcm_token.isnot(None)
            ).order_by(SessionTable.last_seen_at.desc()).first()

            phone_number = None
            if user.phone_number:
                phone_number = f"{user.country_code or ''}{user.phone_number}"

            notificationServices = NotificationServices(
                db=self.db,
                background_tasks=self.background_tasks,
                request=self.request,
                authorization=self.authorization
            )

            notificationServices.send_notification(
                data=NotificationData(
                    user_id=user.user_id,
                    email_address=user.email_address,
                    phone_number=phone_number,
                    fcm_token=active_session.fcm_token if active_session else None,
                    event=NotificationEvent.ACCOUNT_DEACTIVATED,
                    context={
                        "name": user.full_name or user.username or "User",
                        "reason": notification_body,
                    },
                    payload={
                        "event": NotificationEvent.ACCOUNT_DEACTIVATED.value,
                        "reason": "delete_account_requested"
                    },
                    push=True,
                    email=True,
                    sms=False
                )
            )


            # Step 7: Logout from all devices
            sessions = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.is_login == True
            ).all()
            
            for session in sessions:
                session.is_login = False
                session.access_token_hash = None
                session.refresh_token_hash = None
                session.fcm_token = None
                session.logout_at = Helpers.utc6dhaka()

            
            # Step 8: Finalize database changes
            self.db.commit()
            self.db.refresh(delete_record)
            self.db.refresh(new_notification)

            
            # Step 9: Return Responce
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="delete_account_requested",
                message="Delete request submitted successfully",
                data={
                    "scheduled_delete_at": scheduled_delete_at
                },
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # User Account Cancel Delete Request
    def cancel_delete_account(self, payload: CancelDeleteAccountRequest) -> GlobalResponse:
        try:
            # Step 1: Extract payload data
            user_id: str = payload.user_id
            user_password: str = payload.user_password


            # Step 1: Get current user
            user: UserTable = self.request.state.current_user


            # Step 3: Verify password
            if not Hashing.verify_hash(user_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password"
                )


            # Step 4: Find and remove the delete request
            delete_request = self.db.query(DeletedUserTable).filter(
                DeletedUserTable.user_id == user_id,
                DeletedUserTable.is_processed == False
            ).first()

            if not delete_request:
                raise HTTPException(
                    status_code=404,
                    detail="Delete request not found"
                )

            self.db.delete(delete_request)


            # Step 5:  Reactivate account settings
            settings: SettingsTable = user.settings

            if settings:
                settings.account_deactivated = False


            # Step 6: Create notification record and send alerts
            reactivated_notification = NotificationTable(
                target_id=user.user_id,
                type=NotificationType.ALERT,
                title="Delete Account Cancelled",
                body="Your delete account request was cancelled and your account has been reactivated."
            )
            self.db.add(reactivated_notification)
            self.db.flush()

            notificationServices = NotificationServices(
                db=self.db,
                background_tasks=self.background_tasks,
                request=self.request,
                authorization=self.authorization
            )

            notificationServices.send_notification(
                data=NotificationData(
                    user_id=user.user_id,
                    email_address=user.email_address,
                    event=NotificationEvent.ACCOUNT_REACTIVATED,
                    context={
                        "name": user.full_name or user.username or "User",
                    },
                    payload={
                        "event": NotificationEvent.ACCOUNT_REACTIVATED.value,
                        "reason": "delete_account_cancelled"
                    },
                    push=True,
                    email=True,
                    sms=False
                )
            )


            # Step 7: Finalize database changes
            self.db.commit()
            self.db.refresh(reactivated_notification)


            # Step 8: Return Response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="cancel_delete_account",
                message="Delete request cancelled successfully",
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
