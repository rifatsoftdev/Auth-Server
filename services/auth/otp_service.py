from fastapi import HTTPException, Request, BackgroundTasks, status
from sqlalchemy.orm import Session
from datetime import timedelta

from app.constants import ENV, AnsiColor, String
from app.enums import NotificationType, OTPMethod, OTPPurpose, TwoFactorType
from app.model import NotificationTable, OTPTable, SessionTable, TwoFactorTable, UserTable
from app.schema import OTPRequest, GlobalResponse, VerifyOTPRequest, EmailVerificationRequest
from app.utils import Generators, Hashing, Helpers, TwoFactorAuth
from services.auth.token_service import TokenGenerators
from services.notification.notification_services import NotificationServices, NotificationData



class OTPService(TokenGenerators):
    def __init__(
        self,
        db: Session,
        background_tasks: BackgroundTasks,
        request: Request,
        authorization: str
    ):
        TokenGenerators.__init__(self)
        self.db = db
        self.background_tasks = background_tasks
        self.request = request
        self.authorization = authorization

    @staticmethod
    def _is_expired(expires_at) -> bool:
        if not expires_at:
            return False

        now = Helpers.utc6dhaka()
        if expires_at.tzinfo is None:
            now = now.replace(tzinfo=None)

        return expires_at < now

    @staticmethod
    def _enum_value(value) -> str:
        return value.value if hasattr(value, "value") else str(value)

    def _decode_otp_request_token(self, otp_token: str) -> dict:
        # OTP tokens don't have iss/aud claims, skip validation
        token_payload = self._decode_token(otp_token)

        if token_payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.TIME_LIMET_EXPAIRE
            )

        if token_payload.get("token_type") != "otp_token":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_TOKEN_TYPE
            )

        if not token_payload.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_TOKEN
            )

        return token_payload

    def _create_email_verification_token(
        self,
        user: UserTable,
        device_id: str = None,
        device_uuid: str = None,
        requires_otp: bool = False
    ) -> str:
        token, _ = self._create_token(
            expire_min=ENV.OTP_TOKEN_EXPIRE_MIN,
            payload={
                "token_type": String.EMAIL_VERIFICATION_TOKEN,
                "user_id": user.user_id,
                "email_address": user.email_address,
                "device_id": device_id,
                "device_uuid": device_uuid,
                "requires_otp": requires_otp
            }
        )
        return token

    def _decode_email_verification_token(self, token: str) -> dict:
        # Email verification tokens don't have iss/aud claims, skip validation
        token_payload = self._decode_token(token)

        if token_payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_OR_EXPIRED_TOKEN
            )

        if token_payload.get("token_type") != "email_verification":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_TOKEN_TYPE
            )

        if not token_payload.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_TOKEN
            )

        return token_payload

    def _get_otp_user(self, user_id: str) -> UserTable:
        user = self.db.query(UserTable).filter(
            UserTable.user_id == user_id
        ).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=String.USER_NOT_FOUND
            )
        
        return user

    def _get_otp_delivery_address(self, user: UserTable, method: str) -> str:
        if method == OTPMethod.EMAIL.value:
            tfa_method = self.db.query(TwoFactorTable).filter(
                TwoFactorTable.user_id == user.user_id,
                TwoFactorTable.method_type == TwoFactorType.EMAIL,
                TwoFactorTable.is_enabled == True
            ).first()

            if not tfa_method:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email two-factor method is not enabled"
                )
            
            return tfa_method.delivery_address or user.email_address

        if method == OTPMethod.SMS.value:
            tfa_method = self.db.query(TwoFactorTable).filter(
                TwoFactorTable.user_id == user.user_id,
                TwoFactorTable.method_type == TwoFactorType.SMS,
                TwoFactorTable.is_enabled == True
            ).first()

            if not tfa_method:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="SMS two-factor method is not enabled"
                )
            
            phone_number = tfa_method.delivery_address or f"{user.country_code or ''}{user.phone_number or ''}"
            return phone_number or None

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP can only be sent by email or sms"
        )

    def _verify_totp(self, user: UserTable, otp: str) -> None:
        tfa_method = self.db.query(TwoFactorTable).filter(
            TwoFactorTable.user_id == user.user_id,
            TwoFactorTable.method_type == TwoFactorType.TOTP,
            TwoFactorTable.is_enabled == True
        ).first()

        if not tfa_method or not tfa_method.secret_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="TOTP two-factor method is not enabled"
            )

        if not TwoFactorAuth.verify_otp(tfa_method.secret_key, otp):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_OTP
            )

    def _validate_otp_request(
        self,
        token_payload: dict,
        method: str,
        purpose: str,
        device_id: str,
        device_uuid: str
    ) -> None:
        token_device_id = token_payload.get("device_id") or token_payload.get("android_id")
        token_device_uuid = token_payload.get("device_uuid") or token_payload.get("android_uuid")

        if device_id != token_device_id or device_uuid != token_device_uuid:
            raise HTTPException(status_code=401, detail="Invalid Device")

        if purpose != OTPPurpose.LOGIN.value:
            raise HTTPException(status_code=400, detail="Invalid OTP purpose")

    def _send_email_verification_otp(self, user: UserTable, otp: str) -> bool:
        notification_service = NotificationServices(
            db=self.db,
            background_tasks=self.background_tasks,
            request=self.request,
            authorization=self.authorization
        )

        return notification_service.send_notification(
            NotificationData(
                user_id=user.user_id,
                email_address=user.email_address,
                template="auth.otp",
                context={
                    "name": user.full_name,
                    "email": user.email_address,
                    "otp": otp
                },
                push=False,
                email=True,
                sms=False
            )
        )


    def resend_email_verification(
        self,
        payload: EmailVerificationRequest
    ) -> GlobalResponse:
        try:
            token_payload = self._decode_email_verification_token(payload.email_verification_token)
            user = self._get_otp_user(token_payload.get("user_id"))

            if token_payload.get("email_address") and user.email_address != token_payload.get("email_address"):
                raise HTTPException(
                    status_code=401,
                    detail=String.INVALID_OR_EXPIRED_TOKEN
                )

            if user.email_verified:
                return GlobalResponse(
                    status_code=status.HTTP_200_OK,
                    success=True,
                    action="email_verification_resend",
                    message="Email already verified",
                    data={"email_verified": True},
                    next_step={}
                )

            if not token_payload.get("device_id") or not token_payload.get("device_uuid"):
                raise HTTPException(status_code=401, detail=String.INVALID_OR_EXPIRED_TOKEN)

            new_token, _ = self._create_token(
                expire_min=0,
                payload={
                    "token_type": String.EMAIL_VERIFICATION_TOKEN,
                    "user":user,
                    "device_id":token_payload.get("device_id"),
                    "device_uuid":token_payload.get("device_uuid"),
                    'requires_otp':True
                }
            )

            otp = Generators.generate_otp()
            self.db.query(OTPTable).filter(
                OTPTable.user_id == user.user_id
            ).delete()

            otp_record = OTPTable(
                user_id=user.user_id,
                otp_token=new_token,
                device_id=token_payload.get("device_id"),
                device_uuid=token_payload.get("device_uuid"),
                delever_to=user.email_address,
                otp_hash=Hashing.create_hash(otp),
                expires_at=Helpers.utc6dhaka() + timedelta(minutes=ENV.OTP_TOKEN_EXPIRE_MIN)
            )
            self.db.add(otp_record)
            self.db.flush()

            email_sent = self._send_email_verification_otp(user, otp)
            self.db.commit()

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="email_verification_resend",
                message="Verification email sent" if email_sent else "Verification email could not be sent",
                data={
                    "email_sent": email_sent,
                    "email_verification_token": new_token
                },
                next_step={
                    "endpoint": "/auth/verify-new-user-email",
                    "method": "POST",
                    "payload": {
                        "user_id": user.user_id,
                        "otp": "otp",
                        "email_verification_token": new_token,
                        "device_id": token_payload.get("device_id"),
                        "device_uuid": token_payload.get("device_uuid")
                    }
                }
            )

        except HTTPException:
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    def verify_email(self, token: str) -> GlobalResponse:
        try:
            token_payload = self._decode_email_verification_token(token)

            if token_payload.get("requires_otp"):
                raise HTTPException(status_code=400, detail="OTP verification is required")

            if not token_payload.get("email_address"):
                raise HTTPException(status_code=401, detail=String.INVALID_TOKEN)

            user = self._get_otp_user(token_payload.get("user_id"))

            if token_payload.get("email_address") and user.email_address != token_payload.get("email_address"):
                raise HTTPException(status_code=401, detail=String.INVALID_TOKEN)

            send_welcome_notification = not user.email_verified
            user.email_verified = True

            if send_welcome_notification:
                welcome_notification = NotificationTable(
                    target_id=user.user_id,
                    type=NotificationType.ALERT,
                    title="Welcome to PocketPay! 🔐",
                    body="Your account has been successfully set up. Your security is our priority—let’s get started."
                )
                self.db.add(welcome_notification)

            self.db.commit()

            if send_welcome_notification and self.background_tasks:
                try:
                    notification_service = NotificationServices(
                        db=self.db,
                        background_tasks=self.background_tasks,
                        request=self.request,
                        authorization=self.authorization
                    )
                    notification_service.send_notification(
                        NotificationData(
                            user_id=user.user_id,
                            template="auth.welcome",
                            context={
                                "name": user.full_name,
                            },
                            noty_type=NotificationType.ALERT,
                            push=True,
                            sms=False,
                            email=False
                        )
                    )
                except Exception as e:
                    print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     Welcome notification failed: {e}")

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="email_verified",
                message="Email verified successfully",
                data={"email_verified": True},
                next_step={}
            )

        except HTTPException:
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    def send_otp(
        self,
        payload: OTPRequest
    ) -> GlobalResponse:
        try:
            # Step 1:        
            method = self._enum_value(payload.method)
            purpose = self._enum_value(payload.purpose)
            otp_token = payload.otp_token
            device_id = payload.device_id
            device_uuid = payload.device_uuid

            token_payload = self._decode_otp_request_token(otp_token)
            self._validate_otp_request(token_payload, method, purpose, device_id, device_uuid)

            user = self._get_otp_user(token_payload.get("user_id"))
            delever_to = self._get_otp_delivery_address(user, method)

            if not delever_to:
                raise HTTPException(
                    status_code=400,
                    detail="OTP delivery address not found"
                )

            # Step 2: check otp record
            otp_record = self.db.query(OTPTable).filter(
                OTPTable.otp_token == otp_token
            ).first()

            if otp_record:
                self.db.delete(otp_record)
                self.db.flush()
 
            # Step 3: Generate OTP and Hash
            make_otp = Generators.generate_otp()
            otp_hash = Hashing.create_hash(make_otp)

            # Step 4: insert otp data
            otp_record = OTPTable(
                user_id=user.user_id,
                otp_token=otp_token,
                device_id=device_id,
                device_uuid=device_uuid,
                delever_to=delever_to,
                otp_hash=otp_hash,
                expires_at=Helpers.utc6dhaka() + timedelta(minutes=5)
            )
            self.db.add(otp_record)

            if ENV.DEBUG:
                print(f"{AnsiColor.BLUE}INFO{AnsiColor.RESET}:     OTP sent to {delever_to} code {make_otp}")

            # Step 5: send OTP on user
            notification_service = NotificationServices(
                db=self.db,
                background_tasks=self.background_tasks,
                request=self.request,
                authorization=self.authorization
            )
            
            sendStatus: bool = notification_service.send_notification(
                NotificationData(
                    user_id=user.user_id,
                    email_address=delever_to,
                    template="auth.otp",
                    context={
                        "name": user.full_name,
                        "email": delever_to,
                        "otp": make_otp
                    },
                    noty_type="otp",
                    push=False,
                    email=True,
                    sms=False
                )
            )
            
            if not sendStatus:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to send OTP"
                )

            # Step 6: commit and refresh db
            self.db.commit()
            self.db.refresh(otp_record)

            # Step 7: Return Responce
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="otp_resent",
                message="OTP resent successfully",
                data={
                    "otp_token": otp_token,
                    "method": method,
                    "purpose": purpose
                },
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail="Internal server error")


    def verify_otp(
        self,
        payload: VerifyOTPRequest
    ) -> GlobalResponse:
        try:
            method: str = self._enum_value(payload.method)
            purpose: str = self._enum_value(payload.purpose)
            otp: str = payload.otp
            otp_token: str = payload.otp_token
            device_id: str = payload.device_id
            device_uuid: str = payload.device_uuid

            ip: str = self.request.client.host

            token_payload = self._decode_otp_request_token(otp_token)
            self._validate_otp_request(token_payload, method, purpose, device_id, device_uuid)
            user = self._get_otp_user(token_payload.get("user_id"))
            send_welcome_notification = False

            if method == OTPMethod.TOTP.value:
                self._verify_totp(user, otp)
            else:
                otp_record = self.db.query(OTPTable).filter(
                    OTPTable.otp_token == otp_token
                ).first()

                if not otp_record:
                    raise HTTPException(status_code=404, detail=String.OTP_NOT_FOUND)

                if self._is_expired(otp_record.expires_at):
                    self.db.delete(otp_record)
                    self.db.commit()
                    raise HTTPException(status_code=401, detail=String.TIME_LIMET_EXPAIRE)

                if not Hashing.verify_otp(otp, otp_record.otp_hash):
                    raise HTTPException(status_code=401, detail=String.INVALID_OTP)

                expected_delivery_address = self._get_otp_delivery_address(user, method)
                if otp_record.delever_to != expected_delivery_address:
                    raise HTTPException(status_code=400, detail="Invalid OTP method")

                self.db.delete(otp_record)

                if not user.email_verified and method == OTPMethod.EMAIL.value:
                    user.email_verified = True
                    send_welcome_notification = True

                if not user.phone_verified and method == OTPMethod.SMS.value:
                    user.phone_verified = True

                self.db.commit()

            access_token, _ = self._create_token(
                expire_min=ENV.ACCESS_EXPIRE_MINUTES,
                payload={
                    "token_type": String.ACCESS_TOKEN,
                    "user_id": user.user_id,
                    "email_address": user.email_address,
                    "device_id": device_id,
                    "device_uuid": device_uuid,
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    # "aud": ENV.ALLOWED_AUDIENCES,
                }
            )

            refresh_token, _ = self._create_token(
                expire_day=ENV.REFRESH_EXPIRE_DAYS,
                payload={
                    "token_type": String.REFRESH_TOKEN,
                    "user_id": user.user_id,
                    "email_address": user.email_address,
                    "device_id": device_id,
                    "device_uuid": device_uuid,
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    "aud": [f"auth.{ENV.MAIN_DOMAIN}"],
                }
            )

            session = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.device_id == device_id,
                SessionTable.device_uuid == device_uuid,
                SessionTable.refresh_token_hash == None,
                SessionTable.is_login == False
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
                self.db.commit()
                self.db.refresh(session)

            if send_welcome_notification:
                welcome_notification = NotificationTable(
                    target_id=user.user_id,
                    type=NotificationType.ALERT,
                    title="Welcome to PocketPay! 🔐",
                    body="Your account has been successfully set up. Your security is our priority—let’s get started."
                )
                self.db.add(welcome_notification)
                self.db.commit()

                if self.background_tasks:
                    try:
                        notification_service = NotificationServices(
                            db=self.db,
                            background_tasks=self.background_tasks,
                            request=self.request,
                            authorization=self.authorization
                        )
                        notification_service.send_notification(
                            NotificationData(
                                user_id=user.user_id,
                                template="auth.welcome",
                                context={
                                    "name": user.full_name,
                                },
                                noty_type=NotificationType.ALERT,
                                push=True,
                                sms=False,
                                email=False
                            )
                        )
                    except Exception as e:
                        print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     Welcome notification failed: {e}")

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="otp_verified",
                message="OTP verified successfully",
                data={
                    "user_id": user.user_id,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": ENV.ACCESS_EXPIRE_MINUTES,
                    "email_address": user.email_address,
                    "phone_number": user.country_code + user.phone_number
                },
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
