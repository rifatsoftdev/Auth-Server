from fastapi import Request, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from google.oauth2 import id_token
from google.auth.transport import requests

from app.model import UserTable, SessionTable, NotificationTable
from app.enums import NotificationType
from app.constants import ENV, String, AnsiColor
from app.utils import Hashing, Helpers
from services.auth.signup_service import RegistrationService
from app.schema import GoogleLoginRequest, GlobalResponse, LinkGoogleAccountRequest

from services.notification.notification_services import NotificationServices, NotificationData, NotificationEvent

from services.auth.user_verification import UserVerificationService
from services.auth.token_service import TokenGenerators


class GoogleOauth(TokenGenerators):
    def __init__(
        self,
        db: Session,
        background_tasks: BackgroundTasks,
        request: Request,
        authorization: str
    ):
        self.db = db
        self.background_tasks = background_tasks
        self.request = request
        self.authorization = authorization
        super().__init__(self)

    def google_login(self, payload: GoogleLoginRequest) -> GlobalResponse:
        try:
            Helpers.print_payload(payload)
            token_id = payload.token_id
            device_id = payload.device_id
            device_uuid = payload.device_uuid

            # 🔑 Verify token
            idinfo = id_token.verify_oauth2_token(
                token_id,
                requests.Request(),
                audience=ENV.GOOGLE_CLIENT_ID
            )
            
            google_id = idinfo["sub"]
            email_address = idinfo.get("email")
            email_verified = idinfo.get("email_verified")

            # print(google_id)

            # Request info
            ip: str = self.request.client.host
            user_agent: str = self.request.headers.get("user-agent")
            auth: str = self.request.headers.get("authorization")
            path: str = self.request.url.path
            query: dict = dict(self.request.query_params)
            cookies: dict = self.request.cookies

            # print(f"{email_address} {email_verified}")
            if (not email_address or not email_verified):
                raise HTTPException(
                    status_code=400,
                    detail=String.EMAIL_OR_PHONE_REQUIRED
                )
            
            registrationService = RegistrationService(
                db=self.db,
                background_tasks=self.background_tasks,
                request=self.request,
                authorization=self.authorization
            )
            
            existing_user: UserTable = registrationService._check_user_already_exists(
                email=email_address
            )

            if not existing_user:
                raise HTTPException(
                    status_code=404,
                    detail=String.USER_NOT_FOUND
                )

            if not existing_user.link_google:
                raise HTTPException(
                    status_code=400,
                    detail="Google account is not connected"
                )

            if existing_user.link_google != google_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Google account does not match"
                )

            if not existing_user.email_verified:
                response = registrationService.email_verification_required_response(
                    user=existing_user,
                    device_id=device_id,
                    device_uuid=device_uuid
                )
                self.db.commit()
                return response

            user = existing_user

            # Generate access token
            access_token, _ = self._create_token(
                expire_min=ENV.ACCESS_EXPIRE_MINUTES,
                payload={
                    "token_type": "access",
                    "user_id": user.user_id,
                    "email_address": user.email_address,
                    "device_id": device_id,
                    "device_uuid": device_uuid,
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    # "aud": ENV.ALLOWED_AUDIENCES,
                }
            )

            # Generate refresh token
            refresh_token, _ = self._create_token(
                expire_day=ENV.REFRESH_EXPIRE_DAYS,
                payload={
                    "token_type": "refresh",
                    "user_id": user.user_id,
                    "email_address": user.email_address,
                    "device_id": device_id,
                    "device_uuid": device_uuid,
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    "aud": [f"auth.{ENV.MAIN_DOMAIN}"],
                }
            )

            # Update session
            session = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.device_id == device_id,
                SessionTable.device_uuid == device_uuid,
                SessionTable.is_login == True
            ).first()

            if session:
                session.access_token_hash = Hashing.create_hash(access_token)
                session.refresh_token_hash = Hashing.create_hash(refresh_token)
                session.last_ip_address = ip
                session.is_login = True
                session.otp_verified = True
                session.login_at = Helpers.utc6dhaka()
                self.db.commit()
                self.db.refresh(session)
            
            else:
                session = SessionTable(
                    user_id=user.user_id,
                    fcm_token=None,
                    access_token_hash=Hashing.create_hash(access_token),
                    refresh_token_hash=Hashing.create_hash(refresh_token),
                    device_uuid=device_uuid,
                    device_id=device_id,
                    last_ip_address=ip,
                    is_login=True,
                    otp_verified=True,
                )
                self.db.add(session)

                # all commit and refresh
                self.db.commit()
                self.db.refresh(session)
            
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="login",
                message="Login Successful",
                data={
                    "user_id": user.user_id,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "email_address": user.email_address,
                    "phone_number": None
                },
                next_step={}
            )
        
        except HTTPException:
            self.db.rollback()
            raise

        except ValueError:
            self.db.rollback()
            raise HTTPException(
                status_code=401,
                detail=String.INVALID_TOKEN
            )

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail=String.SERVER_ERROR
            )

    def link_google(self, payload: LinkGoogleAccountRequest) -> GlobalResponse:
        try:
            # Step 1: Verify user and token
            user_id: str = payload.user_id
            access_token: str = payload.access_token
            android_id: str = payload.device_id
            android_uuid: str = payload.device_uuid
            token_id: str = payload.token_id

            user_verification_service = UserVerificationService()

            user = user_verification_service.verify_user(
                user_id=user_id,
                access_token=access_token,
                android_id=android_id,
                android_uuid=android_uuid
            )

            idinfo = id_token.verify_oauth2_token(
                token_id,
                requests.Request(),
                ENV.GOOGLE_CLIENT_ID
            )

            google_id: str = idinfo["sub"]
            email_address: str = idinfo.get("email")
            email_verified = idinfo.get("email_verified")
            full_name: str = idinfo.get("name")
            profile_image_url: str = idinfo.get("picture")

            if not email_address:
                raise HTTPException(
                    status_code=400,
                    detail="Google account email not found"
                )

            if not email_verified:
                raise HTTPException(
                    status_code=400,
                    detail="Google account email is not verified"
                )

            if user.email_address.lower() != email_address.lower():
                raise HTTPException(
                    status_code=409,
                    detail="Google account email does not match"
                )

            if user.link_google and user.link_google != google_id:
                raise HTTPException(
                    status_code=409,
                    detail="Another Google account is already connected"
                )

            user.email_verified = True
            user.link_google = google_id

            if profile_image_url and not user.profile_image_url:
                user.profile_image_url = profile_image_url

            if full_name and not user.full_name:
                user.full_name = full_name

            ip: str = self.request.client.host


            # Step 2: Create notification
            new_notification = NotificationTable(
                target_id=user.user_id,
                type=NotificationType.ALERT,
                title="Google Account Linked",
                body=f"Your Google account was linked from IP {ip}."
            )
            self.db.add(new_notification)
            self.db.flush()


            # Step 3: Send Notification
            notification_service = NotificationServices(
                db=self.db,
                background_tasks=self.background_tasks,
                request=self.request,
                authorization=self.authorization,
            )

            notification_service.send_notification(
                NotificationData(
                    event=NotificationEvent.LINK_GOOGLE,
                    user_id=user.user_id,
                    email_address=user.email_address,
                    # fcm_token=session.fcm_token,  # optional
                    email=True,
                    push=True,
                    sms=False,
                    context={},
                    payload={}
                )
            )

            
            # Step 4: Finalize database changes
            self.db.commit()
            self.db.refresh(user)
            self.db.refresh(new_notification)


            # Step 5: Return response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="link_google",
                message="Google account linked successfully",
                data={}
            )
        
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail=String.SERVER_ERROR
            )






# ==============================================================================
# ==============================================================================
