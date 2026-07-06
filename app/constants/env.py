import os, dotenv, json
from decimal import Decimal


dotenv.load_dotenv("/etc/env/.env")


def _get_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class ENV:
    # Server Version and Debug mode
    VERSION: str = os.getenv("VERSION", "2.1.4")
    DEBUG: bool = os.getenv("DEBUG", "True") == "True"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    ENV_FILE_KEY_PATH: str = os.getenv("ENV_FILE_KEY_PATH", "/etc/env/.env")
    PRIVATE_KEY_PATH: str = os.getenv("PRIVATE_KEY_PATH")
    PUBLIC_KEY_PATH: str = os.getenv("PUBLIC_KEY_PATH")

    MAIN_DOMAIN: str = os.getenv("MAIN_DOMAIN", "")
    ALLOWED_ORIGIN_REGEX: str = os.getenv("ALLOWED_ORIGIN_REGEX", ".*")
    

    # Service Charge configuration
    SERVICE_CHARGE: float = float(os.getenv("SERVICE_CHARGE", "1.0"))
    

    # DataBase configuration
    DATABASE_URL: str= os.getenv("DATABASE_URL", "sqlite:///./database.db")


    # Email configuration
    EMAIL_ADDRESS: str = os.getenv("EMAIL_ADDRESS", "")
    EMAIL_PASSWORD: str = os.getenv("EMAIL_PASSWORD", "")
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", 587))
    EMAIL_USE_TLS: bool = _get_bool("EMAIL_USE_TLS", True)
    EMAIL_USE_SSL: bool = _get_bool("EMAIL_USE_SSL", False)


    # Twilio configuration
    TWILIO_ACCOUNT_SID: str = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN: str = os.getenv("TWILIO_AUTH_TOKEN", "")
    TWILIO_PHONE_NUMBER: str = os.getenv("TWILIO_PHONE_NUMBER", "")


    # Cloudinary configuration
    CLOUDINARY_CLOUD_NAME: str = os.getenv("CLOUDINARY_CLOUD_NAME", "")
    CLOUDINARY_API_KEY: str = os.getenv("CLOUDINARY_API_KEY", "")
    CLOUDINARY_API_SECRET: str = os.getenv("CLOUDINARY_API_SECRET", "")
    

    # JWT configuration
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    
    OTP_TOKEN_EXPIRE_MIN: int = int(os.getenv("OTP_TOKEN_EXPIRE_MINUTES", "5"))
    PASS_RST_TOKEN_EXPIRE_MIN: int = int(os.getenv("PASS_RST_TOKEN_EXPIRE_MINUTES", "15"))

    ACCESS_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_EXPIRE_MINUTES", "10"))
    REFRESH_EXPIRE_DAYS: int = int(os.getenv("REFRESH_EXPIRE_DAYS", "30"))


    # Redis configuration
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    EMAIL_QUEUE_NAME: str = os.getenv("EMAIL_QUEUE_NAME", "email_queue")
    EMAIL_FAILED_QUEUE_NAME: str = os.getenv("EMAIL_FAILED_QUEUE_NAME", "email_failed_queue")

    SMS_QUEUE_NAME: str = os.getenv("SMS_QUEUE_NAME", "sms_queue")
    SMS_FAILED_QUEUE_NAME: str = os.getenv("SMS_FAILED_QUEUE_NAME", "sms_failed_queue")

    EMAIL_MAX_ATTEMPTS: int = int(os.getenv("EMAIL_MAX_ATTEMPTS", "5"))
    EMAIL_WORKER_POLL_TIMEOUT: int = int(os.getenv("EMAIL_WORKER_POLL_TIMEOUT", "5"))

    SMS_MAX_ATTEMPTS: int = int(os.getenv("SMS_MAX_ATTEMPTS", "5"))
    SMS_WORKER_POLL_TIMEOUT: int = int(os.getenv("SMS_WORKER_POLL_TIMEOUT", "5"))


    # Salt for password hashing
    SALT: bytes = os.getenv("SALT", "default_salt").encode()


    # Firebase configuration
    FIREBASE_SERVICE_ACCOUNT: str = os.getenv("FIREBASE_SERVICE_ACCOUNT", "")
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")


    # Default admin
    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "dting@gmail.com")
    DEFAULT_ADMIN_PHONE: str = os.getenv("DEFAULT_ADMIN_PHONE", "01700000000")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@123")
    DEFAULT_ADMIN_NAME: str = os.getenv("DEFAULT_ADMIN_NAME", "Admin DTing")


    # Default user
    DEFAULT_USER_EMAIL: str = os.getenv("DEFAULT_USER_EMAIL", "dting@gmail.com")
    DEFAULT_USER_PHONE: str = os.getenv("DEFAULT_USER_PHONE", "01700000000")
    DEFAULT_USER_PASSWORD: str = os.getenv("DEFAULT_USER_PASSWORD", "User@123")
    DEFAULT_USER_NAME: str = os.getenv("DEFAULT_USER_NAME", "DTing")

    

# if __name__ == "__main__":
#     print(ENV.EMAIL_USE_TLS)
#     print(ENV.EMAIL_USE_SSL)
