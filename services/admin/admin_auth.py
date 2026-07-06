from datetime import datetime, timezone, timedelta
from fastapi import BackgroundTasks, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func, desc

from app.constants import AnsiColor, String, ENV
from app.enums import NotificationType
from app.model import DeletedUserTable, NotificationTable, SessionTable, SettingsTable, AdminTable
from app.schema import GlobalResponse, CancelDeleteAccountRequest
from app.utils import Helpers, Generators, Hashing

from app.model.admin_table import AdminTable, AdminRole, ROLE_PERMISSIONS, AdminPermissions

from app.model import SessionTable, UserTable, KYCTable
from services.auth.user_verification import UserVerificationService
from app.schema.auth_schemas import DeleteAccountRequest
from services.auth.user_verification import UserVerificationService

from admin.schema.admin_schema import *
from services.auth.token_service import TokenGenerators



class AdminManagementServices(UserVerificationService, TokenGenerators):
    def __init__(
        self,
        db: Session,
        background_tasks: BackgroundTasks,
        request: Request,
        authorization: str
    ):
        UserVerificationService.__init__(
            self,
            db=db,
            background_tasks=background_tasks,
            request=request,
            authorization=authorization
        )
        TokenGenerators.__init__(self)
    

    def admin_login(
        self,
        payload: AdminLoginRequest
    ) -> GlobalResponse:
        try:
            email = payload.email
            password = payload.password
            device_id = payload.device_id
            device_uuid = payload.device_uuid

            # Request info
            ip = self.request.client.host

            # Find admin
            admin = self.db.query(AdminTable).filter(
                AdminTable.email == email
            ).first()

            if not admin:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Admin not found"
                )

            if not admin.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, 
                    detail="Admin account is inactive"
                )
            
            # Verify password
            if not Hashing.verify_password(password, admin.password_hash):
                raise HTTPException(
                    status_code=401, 
                    detail="Invalid password"
                )

            # Get permissions based on role
            permissions = ROLE_PERMISSIONS.get(AdminRole(admin.role), [])

            session_id = Generators.generate_id("session")
            now = datetime.now(timezone.utc)

            # Current SQLite schema keeps one admin session row per admin_id.
            # Reuse it on repeated login instead of inserting a duplicate admin_id.
            session = self.db.query(SessionTable).filter(
                SessionTable.admin_id == admin.admin_id
            ).first()
            
            if session:
                session.session_id = session_id
                session.device_uuid = device_uuid
                session.device_id = device_id
                session.last_ip_address = ip
                session.is_login = True
                session.login_at = now
                session.logout_at = None
            else:
                session = SessionTable(
                    admin_id=admin.admin_id,
                    owner_type="admin",
                    session_id=session_id,
                    device_uuid=device_uuid,
                    device_id=device_id,
                    last_ip_address=ip,
                    is_login=True,
                    login_at=now
                )
                self.db.add(session)

            self.db.commit()
            self.db.refresh(session)

            # Generate tokens
            access_token, _ = self._create_token(
                expire_min=ENV.ACCESS_EXPIRE_MINUTES,
                payload={
                    "token_type": "access",
                    "admin_id": admin.admin_id,
                    "email_address": admin.email,
                    "role": admin.role,
                    "permissions": permissions,
                    "device_id": device_id,
                    "device_uuid": device_uuid,
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    "aud": ENV.ALLOWED_AUDIENCES,
                }
            )
        
            refresh_token, _ = self._create_token(
                expire_day=ENV.REFRESH_EXPIRE_DAYS,
                payload={
                    "token_type": "refresh",
                    "admin_id": admin.admin_id,
                    "email_address": admin.email,
                    "role": admin.role,
                    "permissions": permissions,
                    "device_id": device_id,
                    "device_uuid": device_uuid,
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    "aud": [f"auth.{ENV.MAIN_DOMAIN}"],
                }
            )
            
            # Update session with token hashes
            session.access_token_hash = Hashing.create_hash(access_token)
            session.refresh_token_hash = Hashing.create_hash(refresh_token)
            self.db.commit()

            # Update last login
            admin.last_login_at = datetime.now(timezone.utc)
            admin.last_ip_address = ip
            self.db.commit()
            
            response = JSONResponse(
                content={
                    "success": True,
                    "message": "Login successful",
                    "data": {
                        "admin_id": admin.admin_id,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "device_id": device_id,
                        "device_uuid": device_uuid
                    }
                }
            )

            response.set_cookie(
                key="admin_access_token",
                value=access_token,
                httponly=False,
                secure=False,
                samesite="lax",
                max_age=60 * ENV.ACCESS_EXPIRE_MINUTES
            )
            response.set_cookie(
                key="admin_refresh_token",
                value=refresh_token,
                httponly=False,
                secure=False,
                samesite="lax",
                max_age=60 * ENV.REFRESH_EXPIRE_DAYS
            )

            return response

        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=String.SERVER_ERROR
            )


    def admin_logout(
        self
    ) -> GlobalResponse:
        try:
            access_token = self.request.cookies.get("admin_access_token")
            refresh_token = self.request.cookies.get("admin_refresh_token")

            # 1️⃣ DB session invalidate
            if access_token:
                token_hash = Hashing.create_hash(access_token)

                session = self.db.query(SessionTable).filter(
                    SessionTable.access_token_hash == token_hash
                ).first()

                if session:
                    session.logout_at = datetime.now(timezone.utc)
                    session.is_login = False
                    self.db.commit()

            # 2️⃣ Response + cookie clear
            response = JSONResponse({
                "success": True,
                "message": "Logged out successfully"
            })

            response.delete_cookie("admin_access_token")
            response.delete_cookie("admin_refresh_token")

            return response
        
        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )
            

    def get_admin_profile(
        self
    ) -> GlobalResponse:
        try:
            # print(self.authorization)
            admin_id: str = self.verify_authorization(self.authorization)
            # print(admin_id)

            current_admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == admin_id
            ).first()

            if (not current_admin):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Admin"
                )

            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                message="Profile retrieved successfully",
                data={
                    "admin_id": current_admin.admin_id,
                    "email": current_admin.email,
                    "full_name": current_admin.full_name,
                    "role": current_admin.role,
                    "permissions": ROLE_PERMISSIONS.get(AdminRole(current_admin.role), []),
                    "is_active": current_admin.is_active,
                    "is_super_admin": current_admin.is_super_admin,
                    "profile_image_url": current_admin.profile_image_url,
                    "last_login_at": current_admin.last_login_at,
                    "created_at": current_admin.created_at
                }
            )

        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )


    def refresh_admin_token(
        self,
        payload: AdminRefreshTokenRequest
    ) -> GlobalResponse:
        try:
            refresh_token = payload.refresh_token
            device_id = payload.device_id
            device_uuid = payload.device_uuid

            if not refresh_token:
                raise HTTPException(
                    status_code=400, 
                    detail="Refresh token is required"
                )

            # Decode the refresh token
            payload = self._decode_token(
                refresh_token,
                audience=f"auth.{ENV.MAIN_DOMAIN}",
                issuer=f"auth.{ENV.MAIN_DOMAIN}"
            )
            
            if not payload:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired refresh token"
                )

            # Check token type
            if payload.get("token_type") != "refresh":
                raise HTTPException(
                    status_code=401,
                    detail="Invalid token type"
                )

            admin_id = payload.get("admin_id")
            if not admin_id:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid token payload"
                )

            # Find admin
            admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == admin_id
            ).first()

            if not admin:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )

            if not admin.is_active:
                raise HTTPException(
                    status_code=403,
                    detail="Admin account is inactive"
                )

            # Verify refresh token hash against session
            session = self.db.query(SessionTable).filter(
                SessionTable.admin_id == admin_id,
                SessionTable.is_login == True
            ).first()

            if not session:
                raise HTTPException(
                    status_code=401,
                    detail="Session not found or expired"
                )

            # Verify refresh token hash
            if not Hashing.verify_hash(refresh_token, session.refresh_token_hash):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid refresh token"
                )

            # Get permissions based on role
            permissions = ROLE_PERMISSIONS.get(AdminRole(admin.role), [])

            # Generate new tokens
            access_token, _ = self._create_token(
                expire_min=ENV.ACCESS_EXPIRE_MINUTES,
                payload={
                    "token_type": "access",
                    "admin_id": admin.admin_id,
                    "email": admin.email,
                    "role": admin.role,
                    "permissions": permissions,
                    "device_id": device_id or payload.get("device_id"),
                    "device_uuid": device_uuid or payload.get("device_uuid"),
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    "aud": ENV.ALLOWED_AUDIENCES,
                }
            )

            new_refresh_token, _ = self._create_token(
                expire_day=ENV.REFRESH_EXPIRE_DAYS,
                payload={
                    "token_type": "refresh",
                    "admin_id": admin.admin_id,
                    "email": admin.email,
                    "role": admin.role,
                    "permissions": permissions,
                    "device_id": device_id or payload.get("device_id"),
                    "device_uuid": device_uuid or payload.get("device_uuid"),
                    "iss": f"auth.{ENV.MAIN_DOMAIN}",
                    "aud": [f"auth.{ENV.MAIN_DOMAIN}"],
                }
            )

            # Update session with new token hashes
            session.access_token_hash = Hashing.create_hash(access_token)
            session.refresh_token_hash = Hashing.create_hash(new_refresh_token)
            self.db.commit()

            response = JSONResponse(
                content={
                    "success": True,
                    "message": "Token refreshed successfully",
                    "data": {
                        "access_token": access_token,
                        "refresh_token": new_refresh_token
                    }
                }
            )

            response.set_cookie(
                key="admin_access_token",
                value=access_token,
                httponly=False,
                secure=False,
                samesite="lax",
                max_age=60 * ENV.ACCESS_EXPIRE_MINUTES
            )
            response.set_cookie(
                key="admin_refresh_token",
                value=new_refresh_token,
                httponly=False,
                secure=False,
                samesite="lax",
                max_age=60 * ENV.REFRESH_EXPIRE_DAYS
            )

            return response

        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )


    def update_own_profile(
        self,
        payload: AdminSelfUpdateRequest,
    ) -> GlobalResponse:
        try:
            admin_id: str = self.verify_authorization(self.authorization)
            current_admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == admin_id
            ).first()

            if not current_admin:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )
            
            if payload.email and payload.email != current_admin.email:
                existing_admin = self.db.query(AdminTable).filter(
                    AdminTable.email == payload.email
                ).first()

                if existing_admin:
                    raise HTTPException(
                        status_code=409,
                        detail="Admin with this email already exists"
                    )
                current_admin.email = payload.email

            if payload.full_name is not None:
                current_admin.full_name = payload.full_name
            if payload.profile_image_url is not None:
                current_admin.profile_image_url = payload.profile_image_url

            current_admin.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(current_admin)

            return GlobalResponse(
                success=True,
                message="Profile updated successfully",
                data={
                    "admin_id": current_admin.admin_id,
                    "email": current_admin.email,
                    "full_name": current_admin.full_name,
                    "profile_image_url": current_admin.profile_image_url,
                    "role": current_admin.role,
                    "is_active": current_admin.is_active,
                    "is_super_admin": current_admin.is_super_admin,
                    "updated_at": current_admin.updated_at
                }
            )

        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )


    def create_admin(self, payload: AdminCreateRequest) -> GlobalResponse:
        try:
            # Check if email already exists
            existing_admin = self.db.query(AdminTable).filter(
                AdminTable.email == payload.email
            ).first()

            if existing_admin:
                raise HTTPException(
                    status_code=409,
                    detail="Admin with this email already exists"
                )
            
            # Create new admin
            admin_id = Generators.generate_id("user")  # Using same generator for admin IDs
            password_hash = Hashing.create_hash(payload.password)
            
            new_admin = AdminTable(
                admin_id=admin_id,
                email=payload.email,
                password_hash=password_hash,
                full_name=payload.full_name,
                profile_image_url=payload.profile_image_url,
                role=payload.role.value,
                is_active=True,
                is_super_admin=False
            )
            
            self.db.add(new_admin)
            self.db.commit()
            self.db.refresh(new_admin)
            
            # Request info
            ip = self.request.client.host
            
            # Log the creation
            new_notification = SessionTable(
                admin_id=admin_id,
                session_id=f"created_by_{new_admin.admin_id}",
                device_uuid=None,
                device_id=None,
                last_ip_address=ip,
                login_at=datetime.now(timezone.utc),
                logout_at=datetime.now(timezone.utc),
                is_login=False
            )
            self.db.add(new_notification)
            self.db.commit()
            
            return GlobalResponse(
                success=True,
                message="Admin created successfully",
                data={
                    "admin_id": new_admin.admin_id,
                    "email": new_admin.email,
                    "full_name": new_admin.full_name,
                    "role": new_admin.role
                }
            )
            
        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )


    def list_admins(
        self,
        page: int,
        limit: int,
        role: Optional[AdminRoleEnum] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
    ) -> GlobalResponse:
        try:
            query = self.db.query(AdminTable)
            
            # Apply filters
            if role:
                query = query.filter(AdminTable.role == role.value)
            if is_active is not None:
                query = query.filter(AdminTable.is_active == is_active)
            if search:
                query = query.filter(
                    or_(
                        AdminTable.email.ilike(f"%{search}%"),
                        AdminTable.full_name.ilike(f"%{search}%"),
                        AdminTable.admin_id.ilike(f"%{search}%")
                    )
                )
            
            # Get total count
            total = query.count()
            
            # Apply pagination
            offset = (page - 1) * limit
            admins = query.order_by(desc(AdminTable.created_at)).offset(offset).limit(limit).all()
            
            # Format response
            admin_list = []
            for admin in admins:
                admin_list.append({
                    "admin_id": admin.admin_id,
                    "email": admin.email,
                    "full_name": admin.full_name,
                    "role": admin.role,
                    "is_active": admin.is_active,
                    "is_super_admin": admin.is_super_admin,
                    "last_login_at": admin.last_login_at,
                    "created_at": admin.created_at
                })
            
            return GlobalResponse(
                success=True,
                message="Admins retrieved successfully",
                data={"admins": admin_list},
                pagination={
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "total_pages": (total + limit - 1) // limit
                }
            )
            
        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )


    def update_admin(self, admin_id: str, payload: AdminUpdateRequest) -> GlobalResponse:
        try:
            admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == admin_id
            ).first()

            if not admin:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )
            
            current_admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == self.verify_authorization(self.authorization)
            ).first()
            
            if not current_admin:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Admin"
                )
            
            if admin_id == current_admin.admin_id:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot modify your own account"
                )
            
            # Prevent changing the last super_admin
            if admin.is_super_admin and admin.role == AdminRole.SUPER_ADMIN.value:
                if payload.role and payload.role != AdminRoleEnum.SUPER_ADMIN:
                    raise HTTPException(
                        status_code=400,
                        detail="Cannot change role of the last super admin"
                    )
                
                if payload.is_active is False:
                    raise HTTPException(
                        status_code=400,
                        detail="Cannot deactivate the last super admin"
                    )
            
            # Update fields
            if payload.full_name is not None:
                admin.full_name = payload.full_name
            if payload.role is not None:
                admin.role = payload.role.value
            if payload.is_active is not None:
                admin.is_active = payload.is_active
            if payload.profile_image_url is not None:
                admin.profile_image_url = payload.profile_image_url
            
            admin.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(admin)
            
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                message="Admin updated successfully",
                data={
                    "admin_id": admin.admin_id,
                    "full_name": admin.full_name,
                    "role": admin.role,
                    "is_active": admin.is_active
                }
            )
            
        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )


    def reset_admin_password(self, payload: AdminPasswordUpdateRequest) -> GlobalResponse:
        try:
            admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == payload.admin_id
            ).first()

            if not admin:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )
            
            # Update password
            admin.password_hash = Hashing.create_hash(payload.new_password)
            admin.updated_at = datetime.now(timezone.utc)
            
            # Invalidate all sessions for this admin
            self.db.query(SessionTable).filter(
                SessionTable.admin_id == payload.admin_id,
                SessionTable.is_login == True
            ).update({
                "is_login": False,
                "logout_at": datetime.now(timezone.utc)
            })
            
            self.db.commit()
            
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                message="Password reset successfully. Admin will need to login again.",
                data={}
            )
            
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}: {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )


    def delete_admin(self, admin_id: str)-> GlobalResponse:
        try:
            admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == admin_id
            ).first()

            if not admin:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )
            
            current_admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == self.verify_authorization(self.authorization)
            ).first()
            
            if not current_admin:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Admin"
                )
            
            if admin_id == current_admin.admin_id:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot delete your own account"
                )
            
            # Prevent deleting the last super_admin
            if admin.is_super_admin:
                super_admin_count = self.db.query(AdminTable).filter(
                    AdminTable.is_super_admin == True,
                    AdminTable.is_active == True
                ).count()

                if super_admin_count <= 1:
                    raise HTTPException(
                        status_code=400,
                        detail="Cannot delete the last super admin"
                    )
            
            # Soft delete - deactivate instead of actual deletion
            admin.is_active = False
            admin.updated_at = datetime.now(timezone.utc)
            
            # Invalidate all sessions
            self.db.query(SessionTable).filter(
                SessionTable.admin_id == admin_id,
                SessionTable.is_login == True
            ).update({
                "is_login": False,
                "logout_at": datetime.now(timezone.utc)
            })
            
            self.db.commit()
            
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                message="Admin deactivated successfully",
                data={}
            )
            
        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )


    def change_own_password(self, payload: AdminChangeOwnPasswordRequest) -> GlobalResponse:
        try:
            admin_id: str = self.verify_authorization(self.authorization)

            current_admin = self.db.query(AdminTable).filter(
                AdminTable.admin_id == admin_id
            ).first()

            if not current_admin:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Admin"
                )
            
            if not Hashing.verify_password(payload.current_password, current_admin.password_hash):
                raise HTTPException(
                    status_code=401,
                    detail="Current password is incorrect"
                )
            
            current_admin.password_hash = Hashing.create_hash(payload.new_password)
            current_admin.updated_at = datetime.now(timezone.utc)
            
            self.db.query(SessionTable).filter(
                SessionTable.admin_id == current_admin.admin_id,
                SessionTable.is_login == True
            ).update({
                "is_login": False,
                "logout_at": datetime.now(timezone.utc)
            })
            
            self.db.commit()
            
            return GlobalResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                action="logout",
                message="Password changed successfully. Please login again.",
                data={}
            )
            
        except HTTPException:
            raise
        
        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )




    
