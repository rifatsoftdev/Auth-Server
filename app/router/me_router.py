from fastapi import APIRouter, BackgroundTasks, Body, Depends, File, Form, Header, Request, UploadFile
from sqlalchemy.orm import Session
from typing import Any, Dict, Optional
from datetime import date

from app.core.database import get_db
from app.core.rate_limit import settings_rate_limit

from app.schema import GlobalResponse
from services import UserServices



me_router = APIRouter()





# ==============================================================================

@me_router.get("/header", response_model=GlobalResponse)
async def profile(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.get_header_data()




# ==============================================================================

@me_router.get("/profile", response_model=GlobalResponse)
async def profile(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.get_profile()



# ==============================================================================

@me_router.get("/settings", response_model=GlobalResponse)
async def settings(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.get_settings()




# ==============================================================================

@me_router.patch("/settings", response_model=GlobalResponse)
@me_router.put("/settings", response_model=GlobalResponse)
async def update_settings(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any] = Body(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    _: None = Depends(settings_rate_limit),
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.update_settings(payload=payload)




# ==============================================================================

@me_router.get("/sessions", response_model=GlobalResponse)
async def sessions(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    start: int = 0,
    end: int = 5,
    db: Session = Depends(get_db)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.get_sessions(
        start=start,
        end=end
    )



@me_router.get("/activities", response_model=GlobalResponse)
async def activities(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    start: int = 0,
    end: int = 5,
    db: Session = Depends(get_db)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.get_activities(
        start=start,
        end=end
    )





# ==============================================================================

@me_router.post("/profile/update", response_model=GlobalResponse)
async def update_profile(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    db: Session = Depends(get_db),

    user_id: str = Form(...),
    device_id: str = Form(...),
    device_uuid: str = Form(...),

    full_name: Optional[str] = Form(None),
    gender: Optional[str] = Form(None),
    date_of_birth: Optional[date] = Form(None),

    profile_picture: Optional[UploadFile] = File(None),
    # avatar: Optional[UploadFile] = File(None),
    # photo: Optional[UploadFile] = File(None),
    # file: Optional[UploadFile] = File(None)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.update_profile(
        user_id=user_id,
        device_id=device_id,
        device_uuid=device_uuid,

        full_name=full_name,
        gender=gender,
        date_of_birth=date_of_birth,
        profile_picture=profile_picture
    )




# ==============================================================================

@me_router.get("/kyc/status", response_model=GlobalResponse)
async def kyc_status(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.get_kyc_status()




# ==============================================================================

@me_router.post("/kyc/submit", response_model=GlobalResponse)
async def kyc_submit(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    db: Session = Depends(get_db),

    document_type: str = Form(...),
    user_id: str = Form(...),
    access_token: str = Form(...),
    device_id: str = Form(...),
    device_uuid: str = Form(...),

    front_image: UploadFile = File(...),
    back_image: UploadFile = File(...),
    user_face_image: UploadFile = File(...)
):
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.kyc_submit(
        document_type=document_type,
        user_id=user_id,
        access_token=access_token,
        device_id=device_id,
        device_uuid=device_uuid,
        front_image=front_image,
        back_image=back_image,
        user_face_image=user_face_image
    )




# ==============================================================================

@me_router.get("/security-center", response_model=GlobalResponse)
async def security_center(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Get user security center information.
    """
    userServices = UserServices(
        db=db,
        background_tasks=background_tasks,
        request=request,
        authorization=authorization
    )

    return userServices.get_security_center()






# ==============================================================================
# ==============================================================================
