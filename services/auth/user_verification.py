from fastapi import HTTPException, status, Request, BackgroundTasks
from sqlalchemy.orm import Session
from jose import JWTError

from app.constants import AnsiColor, String, ENV

from app.utils.hashing import Hashing
from app.enums import KYCStatus
from app.model import UserTable, SettingsTable, SessionTable, AdminTable, KYCTable
from services.auth.repository import Repository
from services.auth.token_service import TokenService



class UserVerificationService(TokenService, Repository):
    def __init__(
        self,
        db: Session | None = None,
        background_tasks: BackgroundTasks | None = None,
        request: Request | None = None,
        authorization: str | None = None
    ):
        TokenService.__init__(
            self,
            db=db,
            background_tasks=background_tasks,
            request=request,
            authorization=authorization,
        )

        Repository.__init__(self, db)

    def __bearer_2_token(self, authorization: str) -> str:
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header"
            )

        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )

        return authorization.split(" ")[1]


    # User authorization function
    def verify_user_authorization(
        self,
        device_id: str = None,
        device_uuid: str = None,
        user_password: str = None,
        advance_check: bool = False
    ) -> UserTable:
        try:
            # Step 1: Check database session
            if self.db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=String.SERVER_ERROR
                )
            

            # Step 2: Decode and validate token
            payload: dict = self._decode_token(
                self.__bearer_2_token(self.authorization),
                audience=ENV.MAIN_DOMAIN,
                issuer=f"api.auth{ENV.MAIN_DOMAIN}"
            )

            if not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_OR_EXPIRED_TOKEN
                )

            if (payload.get("token_type") != "access"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_TOKEN_TYPE
                )
            

            # Step 3: Fetch user, kyc, and session
            user: UserTable = self._get_user(payload.get("user_id"))
            # kyc: KYCTable = self.__get_kyc(user.user_id)
            if device_id and device_uuid:
                session: SessionTable = self._get_session(
                    user_id=user.user_id,
                    device_id=device_id,
                    device_uuid=device_uuid
                )


            # Step 4: verify user id
            if payload.get("user_id") != user.user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_OR_EXPIRED_TOKEN
                )
            

            # Step 5: verify password if provided
            if user_password:
                if (not user.password_hash):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=String.PASSWORD_NOT_SET
                    )
                
                if not Hashing.verify_password(user_password, user.password_hash):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=String.INVALID_PASSWORD
                    )
            

            # Step 6: checks Account status and session
            if (self._get_settings(user.user_id).account_deactivated):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.ACCOUNT_LOCKED
                )
            if device_id and device_uuid:
                if not session.is_login:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=String.USER_NOT_LOGIN
                    )


            # Step 7: Verify KYC if advance check is enabled
            # if (advance_check and kyc.kyc_status != KYCStatus.VERIFIED):
            #     raise HTTPException(
            #         status_code=status.HTTP_401_UNAUTHORIZED,
            #         detail=String.VERIFY_KYC_FIRST
            #     )


            return user
    
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_OR_EXPIRED_TOKEN
            )
            
        except HTTPException:
            raise

        except Exception as e:
            print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=String.SERVER_ERROR
            )
    

    # Admin authorization function
    def verify_admin_authorization(
        self,
        device_id: str = None,
        device_uuid: str = None,
        user_password: str = None,
        advance_check: bool = False
    ) -> AdminTable:
        try:
            # Step 1: Check database session
            if self.db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=String.SERVER_ERROR
                )
            

            # Step 2: Decode and validate token
            payload: dict = self._decode_token(
                self.__bearer_2_token(self.authorization),
                audience=ENV.MAIN_DOMAIN,
                issuer=f"api.auth.{ENV.MAIN_DOMAIN}"
            )

            if not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_OR_EXPIRED_TOKEN
                )

            if (payload.get("token_type") != "access"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_TOKEN_TYPE
                )
            

            # Step 3: Fetch user, kyc, and session
            admin: AdminTable = self._get_admin(payload.get("admin_id"))
            device_id = device_id or payload.get("device_id")
            device_uuid = device_uuid or payload.get("device_uuid")
            session: SessionTable = self._get_session(
                user_id=admin.admin_id,
                device_id=device_id,
                device_uuid=device_uuid,
                admin=True
            )


            # Step 4: verify admin id
            if payload.get("admin_id") != admin.admin_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.INVALID_OR_EXPIRED_TOKEN
                )
            

            # Step 5: verify password if provided
            if user_password:
                if (not admin.password_hash):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=String.PASSWORD_NOT_SET
                    )
                
                if not Hashing.verify_password(user_password, admin.password_hash):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=String.INVALID_PASSWORD
                    )


            # Step 6: checks Account status and session
            # if (self._get_settings(admin.admin_id).account_deactivated):
            #     raise HTTPException(
            #         status_code=status.HTTP_401_UNAUTHORIZED,
            #         detail=String.ACCOUNT_LOCKED
            #     )

            if not session.is_login:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.USER_NOT_LOGIN
                )

            
            if not session.is_login:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=String.ADMIN_NOT_LOGIN
                )


            return admin

        except HTTPException:
            raise

        except Exception as e:
            # print(f"{AnsiColor.RED}INFO{AnsiColor.RESET}:     {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=String.SERVER_ERROR
            )


    # Admin authorization function
    def verify_app_token(self, access_token: str, advanced: bool = False) -> str:
        payload: dict = self._decode_token(
            access_token,
            audience=f"auth.{ENV.MAIN_DOMAIN}",
            issuer=f"auth.{ENV.MAIN_DOMAIN}"
        )
        
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid App Token"
            )

        if (payload.get("token_type") != "app"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=String.INVALID_TOKEN_TYPE
            )

        # if payload.get("user_id") != user_id:
        #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=String.INVALID_TOKEN)
        
        return payload.get("app_id")





# ==============================================================================
# ==============================================================================
