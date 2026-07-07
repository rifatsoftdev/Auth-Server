import traceback
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, BackgroundTasks, UploadFile, status
from sqlalchemy.orm import Session
from datetime import date, datetime

from app.constants import AnsiColor, String, ENV
from app.enums import KYCStatus, UserActivityType, ActivityStatus
from app.schema import GlobalResponse
from app.model import SessionTable, UserTable, SettingsTable, KYCTable, UserActivityTable, UserServicesTable, TwoFactorTable
from app.utils import Helpers

from app.utils.cloudinary_storage import CloudinaryStorage



ALLOWED_TYPES = ["image/*", "image/jpeg", "image/jpg", "image/png", "image/webp"]
MAX_SIZE = 5 * 1024 * 1024  # 5MB


class UserServices:
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
    
    def _serialize_activity(self, activity: UserActivityTable | None) -> dict:
        if not activity:
            return None

        return {
            "id": activity.id,
            "activity_type": self._enum_value(activity.activity_type),
            "detail": activity.detail,
            "ip_address": activity.ip_address,
            "user_agent": activity.user_agent,
            "created_at": activity.created_at.isoformat() if activity.created_at else None
        }

    @staticmethod
    def _format_date_of_birth(value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.date().isoformat()
        if isinstance(value, date):
            return value.isoformat()
        return str(value).split("T", 1)[0].split(" ", 1)[0]

    @staticmethod
    def _enum_value(value):
        return value.value if hasattr(value, "value") else value

    @staticmethod
    def _serialize_settings(settings: SettingsTable | None):
        return {
            column.name: (
                getattr(settings, column.name).isoformat()
                if settings and isinstance(getattr(settings, column.name), datetime)
                else getattr(settings, column.name, None)
            )
            for column in SettingsTable.__table__.columns
        }

    @staticmethod
    def _normalize_setting_value(value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value

    @staticmethod
    def _serialize_session(session: SessionTable | None):
        if not session:
            return None

        return {
            "id": session.id,
            "session_id": session.session_id,
            "device_id": session.device_id,
            "device_uuid": session.device_uuid,
            "device_type": session.device_type,
            "device_name": session.device_name,
            "last_ip_address": session.last_ip_address,
            "otp_verified": session.otp_verified,
            "is_login": session.is_login,
            "last_seen_at": session.last_seen_at.isoformat() if session.last_seen_at else None,
            "login_at": session.login_at.isoformat() if session.login_at else None,
            "logout_at": session.logout_at.isoformat() if session.logout_at else None
        }

    @staticmethod
    def _serialize_kyc(kyc: KYCTable | None) -> dict:
        if not kyc:
            return {
                "status": "not_submitted",
                "document_type": None,
                "rejection_reason": None,
                "submitted_at": None,
                "updated_at": None
            }

        return {
            "status": kyc.kyc_status.value if hasattr(kyc.kyc_status, "value") else kyc.kyc_status,
            "document_type": kyc.document_type,
            "rejection_reason": kyc.rejection_reason,
            "submitted_at": kyc.created_at.isoformat() if kyc.created_at else None,
            "updated_at": kyc.updated_at.isoformat() if kyc.updated_at else None
        }


    
    def get_active_user_services(self) -> list[dict]:
        try:
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user
            

            services = self.db.query(UserServicesTable).filter(
                UserServicesTable.user_id == user.user_id
            ).all()

            result = []

            for service in services:
                result.append({
                    "id": service.id,
                    "user_id": service.user_id,
                    "service_name": service.service_name,
                    "service_slug": service.service_slug,
                    "service_details": service.service_details,
                    "status": service.status.value if service.status else None,
                    "enabled": True,
                    "created_at": service.created_at.isoformat() if service.created_at else None,
                    "updated_at": service.updated_at.isoformat() if service.updated_at else None,
                })

            return result

        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)
    

    def add_user_service(self, service_slug: str) -> dict:
        # Step 1: Get current user
        user: UserTable = self.request.state.current_user
        

        existing: UserServicesTable = self.db.query(UserServicesTable).filter(
            UserServicesTable.user_id == user.user_id,
            UserServicesTable.service_slug == service_slug
        ).first()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Service already enabled for this user"
            )

        
        
        status_value = ActivityStatus.ACTIVE

        if not service_name:
            service_name = " ".join(part.capitalize() for part in service_slug.split("-"))

        service = UserServicesTable(
            user_id=user_id,
            service_slug=service_slug,
            service_name=service_name,
            service_details=service_details,
            status=status_value,
        )
        self.db.add(service)
        self.db.commit()
        self.db.refresh(service)

        return {
            "id": service.id,
            "user_id": service.user_id,
            "service_name": service.service_name,
            "service_slug": service.service_slug,
            "service_details": service.service_details,
            "status": service.status.value if service.status else None,
            "enabled": True,
            "created_at": service.created_at.isoformat() if service.created_at else None,
            "updated_at": service.updated_at.isoformat() if service.updated_at else None,
        }


    @classmethod
    def update_user_service(
        cls,
        db: Session,
        user_id: str,
        service_slug: str,
        service_name: str | None = None,
        service_details: dict | None = None,
        service_status: str | None = None,
    ) -> dict:
        service = db.query(UserServicesTable).filter(
            UserServicesTable.user_id == user_id,
            UserServicesTable.service_slug == service_slug
        ).first()
        if not service:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service not found for this user"
            )

        if service_name is not None:
            service.service_name = service_name
        if service_details is not None:
            service.service_details = service_details
        if service_status is not None:
            from app.enums import ActivityStatus
            try:
                service.status = ActivityStatus(service_status.lower())
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid service status"
                )

        db.commit()
        db.refresh(service)

        return {
            "id": service.id,
            "user_id": service.user_id,
            "service_name": service.service_name,
            "service_slug": service.service_slug,
            "service_details": service.service_details,
            "status": service.status.value if service.status else None,
            "enabled": True,
            "created_at": service.created_at.isoformat() if service.created_at else None,
            "updated_at": service.updated_at.isoformat() if service.updated_at else None,
        }

    @classmethod
    def delete_user_service(cls, db: Session, user_id: str, service_slug: str) -> None:
        service = db.query(UserServicesTable).filter(
            UserServicesTable.user_id == user_id,
            UserServicesTable.service_slug == service_slug
        ).first()
        if not service:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service not found for this user"
            )

        db.delete(service)
        db.commit()


    def get_header_data(self) -> GlobalResponse:
        try:
            user: UserTable = self.request.state.current_user
            
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="header_fetched",
                message="Header fetched successfully",
                data={
                    "header_data": {
                        "user_id": user.user_id,
                        "full_name": user.full_name,
                        "username": user.username,
                        "avatar_url": user.profile_image_url,
                        "notification_count": 0
                    }
                },
                next_step={}
            )
        
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)

    
    # a function of get user profile information
    def get_profile(self) -> GlobalResponse:
        try:
            user: UserTable = self.request.state.current_user

            last_login_session = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.is_login == True
            ).order_by(SessionTable.login_at.desc()).first()

            settings: SettingsTable | None = user.settings
            
            if not settings:
                settings = self.db.query(SettingsTable).filter(
                    SettingsTable.user_id == user.user_id
                ).first()

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="profile_fetched",
                message="Profile fetched successfully",
                data={
                    "profile": {
                        "full_name": user.full_name,
                        "username": user.username or "null",
                        "email_address": user.email_address,
                        "phone_number": f"{user.country_code or ''}{user.phone_number or ''}",
                        "country_code": user.country_code,
                        "gender": self._enum_value(user.user_gender),
                        "date_of_birth": self._format_date_of_birth(user.date_of_birth),
                        "phone_verified": user.phone_verified,
                        "email_verified": user.email_verified,
                        "link_google": user.link_google,
                        "profile_picture": user.profile_image_url,
                        "created_at": user.created_at.isoformat() if user.created_at else None,
                        "last_login": last_login_session.login_at.isoformat() if last_login_session and last_login_session.login_at else None,
                        "bio": None,
                        "locale": None,
                        "timezone": settings.timezone if settings and settings.timezone else None
                    }
                }
            )
        
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # a function to get user settings information
    def get_settings(self) -> GlobalResponse:
        try:
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user


            # Step 2: Fetch user settings data
            user: UserTable = self.db.query(UserTable).filter(
                UserTable.user_id == user.user_id
            ).first()

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=String.USER_NOT_FOUND
                )

            settings: SettingsTable = user.settings

            if not settings:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=String.SETTINGS_NOT_FOUND
                )

            # Stap 3: Return settings response
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="settings_fetched",
                message="Settings fetched successfully",
                data={
                    "settings": self._serialize_settings(settings)
                },
                next_step={}
            )
        
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # a function to get user session information
    def get_sessions(
        self,
        start: int = 0,
        end: int = 5
    ) -> GlobalResponse:
        try:
            if start < 0 or end < 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="start and end must be greater than or equal to 0"
                )

            if end <= start:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="end must be greater than start"
                )

            # Step 1: Get current user
            user: UserTable = self.request.state.current_user

            query = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id
            ).order_by(SessionTable.id.asc())

            total = query.count()
            sessions = query.offset(start).limit(end - start).all()
            data = {
                "start": start,
                "end": end,
                "count": len(sessions),
                "total": total,
                "sessions": [
                    self._serialize_session(session)
                    for session in sessions
                ]
            }


            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="sessions_fetched",
                message="Sessions fetched successfully",
                data=data,
                next_step={}
            )
        
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # get user activities
    def get_activities(
        self,
        start: int = 0,
        end: int = 5
    ) -> GlobalResponse:
        try:
            if start < 0 or end < 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="start and end must be greater than or equal to 0"
                )

            if end <= start:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="end must be greater than start"
                )

            # Step 1: Get current user
            user: UserTable = self.request.state.current_user
            

            query = self.db.query(UserActivityTable).filter(
                UserActivityTable.user_id == user.user_id
            ).order_by(UserActivityTable.id.desc())

            total = query.count()
            activities = query.offset(start).limit(end - start).all()
            data = {
                "start": start,
                "end": end,
                "count": len(activities),
                "total": total,
                "activities": [
                    self._serialize_activity(a)
                    for a in activities
                ]
            }

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="activities_fetched",
                message="Activities fetched successfully",
                data=data,
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    def get_kyc_status(self) -> GlobalResponse:
        try:
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user
            

            kyc = self.db.query(KYCTable).filter(
                KYCTable.user_id == user.user_id
            ).first()

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="kyc_status_fetched",
                message="KYC status fetched successfully",
                data={"kyc": self._serialize_kyc(kyc)},
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # a function to get security center
    def get_security_center(self) -> GlobalResponse:
        try:
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user

            settings: SettingsTable = user.settings

            if not settings:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=String.SETTINGS_NOT_FOUND
                )

            enabled_tfa = self.db.query(TwoFactorTable).filter(
                TwoFactorTable.user_id == user.user_id,
                TwoFactorTable.is_enabled == True
            ).all()

            enabled_tfa_methods = [
                {
                    "method": method.method_type.value,
                    "delivery_address": method.delivery_address,
                    "is_primary": method.is_primary,
                    "enabled_at": method.created_at.isoformat() if method.created_at else None
                }
                for method in enabled_tfa
            ]

            # determine available TFA methods and totals
            from app.enums import TwoFactorType
            all_methods = [TwoFactorType.TOTP, TwoFactorType.EMAIL, TwoFactorType.SMS]
            enabled_method_types = {method.method_type for method in enabled_tfa}
            available_methods = [m.value for m in all_methods if m not in enabled_method_types]
            total_enabled = len(enabled_tfa_methods)

            last_login_session = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.is_login == True
            ).order_by(SessionTable.login_at.desc()).first()

            active_sessions = self.db.query(SessionTable).filter(
                SessionTable.user_id == user.user_id,
                SessionTable.is_login == True
            ).count()

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="security_center_fetched",
                message="Security center data fetched successfully",
                data={
                    "security": {
                        "last_password_changed_at": settings.last_password_changed_at.isoformat() if settings.last_password_changed_at else None,
                        "password_change_alerts": settings.password_change_alerts,
                        "login_alerts": settings.login_alerts,
                        "new_device_alerts": settings.new_device_alerts,
                        "biometric_enabled": settings.biometric_enabled,
                        "biometric_enabled_at": settings.biometric_enabled_at.isoformat() if settings.biometric_enabled_at else None,
                        "account_deactivated": settings.account_deactivated,
                        "deactivated_at": settings.deactivated_at.isoformat() if settings.deactivated_at else None,
                        "email_verified": user.email_verified,
                        "phone_verified": user.phone_verified,
                        "google_linked": bool(user.link_google),
                        "enabled_tfa_methods": enabled_tfa_methods,
                        "enabled_methods": enabled_tfa_methods,
                        "available_methods": available_methods,
                        "total_enabled": total_enabled,
                        "active_sessions": active_sessions,
                        "last_login_at": last_login_session.login_at.isoformat() if last_login_session else None
                    }
                },
                next_step={}
            )

        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # a function to submit kyc information
    def kyc_submit(
        self,
        document_type: str,
        user_id: str,
        access_token: str,
        device_id: str,
        device_uuid: str,
        front_image: UploadFile,
        back_image: UploadFile,
        user_face_image: UploadFile
    ):
        try:
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user

            old_kyc = self.db.query(KYCTable).filter(
                KYCTable.user_id == user.user_id
            ).first()

            old_status = self._enum_value(old_kyc.kyc_status) if old_kyc else None
            if old_status == KYCStatus.VERIFIED.value:
                raise HTTPException(
                    status_code=400,
                    detail="KYC already verified. If you want to update your KYC, please contact support."
                )

            elif old_status == KYCStatus.PENDING.value:
                raise HTTPException(
                    status_code=400,
                    detail="KYC already pending. We are reviewing your documents and will update your KYC status accordingly."
                )

            cloudinaryStorage = CloudinaryStorage(db=self.db)
            url_results = []

            for file in [front_image, back_image, user_face_image]:
                if file.content_type and not file.content_type.startswith("image/"):
                    raise HTTPException(
                        status_code=400,
                        detail="Only image files allowed"
                    )

                file.file.seek(0, 2)
                size = file.file.tell()
                file.file.seek(0)

                if size > MAX_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail="Image size must be under 5MB"
                    )

                image_url = cloudinaryStorage.upload_file(
                    file_path=file.file,
                    public_id=f"{user.user_id}/kyc/{file.filename}",
                    file_type="image"
                )
                if not image_url:
                    raise HTTPException(
                        status_code=502,
                        detail="Cloudinary upload failed: no upload response received"
                    )

                image_url_value = image_url.get("secure_url") or image_url.get("url")
                if not image_url_value:
                    raise HTTPException(
                        status_code=502,
                        detail="Cloudinary upload failed: image URL missing"
                    )

                url_results.append(image_url_value)
            
            if old_status == KYCStatus.REJECTED.value:
                # update kyc info
                old_kyc.document_type = document_type
                old_kyc.front_image_url = url_results[0]
                old_kyc.back_image_url = url_results[1]
                old_kyc.user_face_image_url = url_results[2]
                old_kyc.kyc_status = KYCStatus.PENDING.value
                old_kyc.updated_at = datetime.utcnow()

                self.db.commit()
                self.db.refresh(old_kyc)

                return GlobalResponse(
                    status_code=status.HTTP_200_OK,
                    message="KYC documents resubmitted successfully. Your KYC status is now pending. We will review your documents and update your KYC status accordingly.",
                    data={
                        "kyc_status": "pending"
                    },
                    next_step={}
                )

            # update user kyc info
            user_kyc = KYCTable(
                user_id=user.user_id,
                document_type=document_type,
                front_image_url=url_results[0],
                back_image_url=url_results[1],
                user_face_image_url=url_results[2]
            )

            self.db.add(user_kyc)
            self.db.commit()
            self.db.refresh(user_kyc)

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                message="KYC documents submitted successfully. Your KYC status is now pending. We will review your documents and update your KYC status accordingly.",
                action="kyc_submitted",
                data={
                    "kyc_status": "pending"
                },
                next_step={}
            )
            
        except HTTPException:
            raise
            
        except Exception as e:
            print(f"{AnsiColor.RED}ERROR{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # 
    def update_profile(
        self,
        user_id: str,
        device_id: str,
        device_uuid: str,

        full_name: Optional[str] = None,
        gender: Optional[str] = None,
        date_of_birth: Optional[date] = None,
        profile_picture: Optional[UploadFile] = None
    ) -> GlobalResponse:
        try:
            print(
                f"{AnsiColor.BLUE}INFO{AnsiColor.RESET}: /profile/update content-type="
                f"{self.request.headers.get('content-type')}"
            )

            # Step 1: Get current user
            user: UserTable = self.request.state.current_user

            
            # capture old values for activity logging
            old_values = {
                "full_name": user.full_name if user else None,
                "gender": user.user_gender if user else None,
                "date_of_birth": user.date_of_birth if user else None,
                "profile_image_url": user.profile_image_url if user else None
            }

            if full_name is not None:
                user.full_name = full_name

            if gender is not None:
                normalized_gender = gender.strip().lower()
                if normalized_gender not in ["male", "female", "other", "undefined"]:
                    raise HTTPException(status_code=400, detail="Invalid gender value")
                user.user_gender = normalized_gender

            if date_of_birth is not None:
                user.date_of_birth = date_of_birth

            if profile_picture is not None:
                print(
                    f"{AnsiColor.BLUE}INFO{AnsiColor.RESET}: profile photo received "
                    f"filename={profile_picture.filename}, content_type={profile_picture.content_type}"
                )

                if profile_picture.content_type and profile_picture.content_type not in ALLOWED_TYPES:
                    raise HTTPException(
                        status_code=400,
                        detail="Only JPG, PNG, WEBP images allowed"
                    )

                profile_picture.file.seek(0, 2)
                size = profile_picture.file.tell()
                profile_picture.file.seek(0)

                if size > MAX_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail="Image size must be under 5MB"
                    )

                try:
                    cloudinaryStorage = CloudinaryStorage(db=self.db)

                    upload_result = cloudinaryStorage.upload_file(
                        file_path=profile_picture.file,
                        public_id=f"{user.user_id}/profile_photo",
                        file_type="image"
                    )
                    if not upload_result:
                        raise HTTPException(
                            status_code=502,
                            detail="Cloudinary upload failed: no upload response received"
                        )

                    uploaded_url = upload_result.get("secure_url") or upload_result.get("url")
                    if not uploaded_url:
                        raise HTTPException(
                            status_code=502,
                            detail="Cloudinary upload failed: image URL missing"
                        )

                    print(
                        f"{AnsiColor.BLUE}INFO{AnsiColor.RESET}: cloudinary upload success "
                        f"secure_url={uploaded_url}"
                    )
                except HTTPException:
                    raise
                except Exception as upload_error:
                    print(f"{AnsiColor.RED}ERROR{AnsiColor.RESET}: Cloudinary upload failed -> {upload_error}")
                    traceback.print_exc()
                    raise HTTPException(
                        status_code=502,
                        detail=f"Cloudinary upload failed: {str(upload_error)}"
                    )

                user.profile_image_url = uploaded_url
            else:
                print(
                    f"{AnsiColor.YELLOW}INFO{AnsiColor.RESET}: no profile photo received. "
                    "Use one file key: profile_photo/avatar/photo/file/profile_picture"
                )

            self.db.commit()
            self.db.refresh(user)

            # prepare activity details
            try:
                changes = {}
                if old_values.get("full_name") != user.full_name:
                    changes["full_name"] = {"old": old_values.get("full_name"), "new": user.full_name}

                if str(old_values.get("gender")) != str(user.user_gender):
                    changes["gender"] = {"old": self._enum_value(old_values.get("gender")), "new": self._enum_value(user.user_gender)}

                if (old_values.get("date_of_birth") and user.date_of_birth and
                        old_values.get("date_of_birth") != user.date_of_birth):
                    changes["date_of_birth"] = {"old": str(old_values.get("date_of_birth")), "new": str(user.date_of_birth)}

                if old_values.get("profile_image_url") != user.profile_image_url:
                    changes["profile_image_url"] = {"old": old_values.get("profile_image_url"), "new": user.profile_image_url}

                # insert NAME_CHANGE activity if name changed
                if "full_name" in changes:
                    try:
                        name_activity = UserActivityTable(
                            user_id=user.user_id,
                            activity_type=UserActivityType.NAME_CHANGE,
                            detail={"old": changes["full_name"]["old"], "new": changes["full_name"]["new"]},
                            ip_address=(self.request.client.host if getattr(self.request, 'client', None) else None),
                            user_agent=self.request.headers.get("user-agent")
                        )
                        self.db.add(name_activity)
                        self.db.commit()
                    except Exception:
                        self.db.rollback()

                # insert PROFILE_UPDATE activity if any profile fields changed
                if changes:
                    try:
                        profile_activity = UserActivityTable(
                            user_id=user.user_id,
                            activity_type=UserActivityType.PROFILE_UPDATE,
                            detail=changes,
                            ip_address=(self.request.client.host if getattr(self.request, 'client', None) else None),
                            user_agent=self.request.headers.get("user-agent")
                        )
                        self.db.add(profile_activity)
                        self.db.commit()
                    except Exception:
                        self.db.rollback()
            except Exception:
                # ensure activity logging failure does not break profile update
                try:
                    self.db.rollback()
                except Exception:
                    pass

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="profile_updated",
                message="Profile updated successfully",
                data={
                    "profile_picture": user.profile_image_url
                },
                next_step={}
            )
        
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)


    # 
    def update_settings(self, payload: Dict[str, Any]) -> GlobalResponse:
        try:
            # Step 1: Get current user
            user: UserTable = self.request.state.current_user

        
            settings: SettingsTable = self.db.query(SettingsTable).filter(
                SettingsTable.user_id == user.user_id
            ).first()

            if not settings:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=String.SETTINGS_NOT_FOUND
                )

            blocked_fields = {
                "user_id",
                "account_deactivated",
                "deactivated_at",
                "last_password_changed_at",
                "biometric_enabled_at",
                "biometric_secret",
                "created_at",
                "updated_at"
            }
            allowed_fields = {
                column.name
                for column in SettingsTable.__table__.columns
                if column.name not in blocked_fields
            }

            update_data = {
                key: self._normalize_setting_value(value)
                for key, value in payload.items()
                if key in allowed_fields
            }

            invalid_fields = sorted(set(payload.keys()) - allowed_fields - blocked_fields)
            if invalid_fields:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid settings field(s): {', '.join(invalid_fields)}"
                )

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No settings data provided"
                )

            for field, value in update_data.items():
                setattr(settings, field, value)

            # Log activity
            ip_address = self.request.client.host if self.request else None
            user_agent = self.request.headers.get("user-agent") if self.request else None
            
            activity = UserActivityTable(
                user_id=user.user_id,
                activity_type=UserActivityType.SETTINGS_CHANGE,
                detail={
                    "action": "settings_updated",
                    "changed_fields": list(update_data.keys()),
                    "timestamp": str(datetime.now())
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            self.db.add(activity)

            self.db.commit()
            self.db.refresh(settings)

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="settings_updated",
                message="Settings updated successfully",
                data={"settings": self._serialize_settings(settings)},
                next_step={}
            )

        except HTTPException:
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(status_code=500, detail=String.SERVER_ERROR)
    
    

    # get_tfa_methods_status removed — functionality exposed via get_security_center
            




# ==============================================================================
# ==============================================================================
