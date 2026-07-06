import hashlib
import hmac

from passlib.context import CryptContext

from app.constants import ENV

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
LONG_VALUE_HASH_PREFIX = "sha256$"
MAX_BCRYPT_BYTES = 72


class Hashing:
    @staticmethod
    def _long_value_hash(value: str) -> str:
        secret = (ENV.JWT_SECRET_KEY or ENV.SALT or "pocketpay").encode("utf-8")
        digest = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{LONG_VALUE_HASH_PREFIX}{digest}"

    @staticmethod
    def create_hash(password: str) -> str:
        """Hash a password."""
        if len(password.encode("utf-8")) > MAX_BCRYPT_BYTES:
            return Hashing._long_value_hash(password)
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_otp(plain_otp: str, hashed_otp: str) -> bool:
        return pwd_context.verify(plain_otp.strip(), hashed_otp)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        if hashed_password.startswith(LONG_VALUE_HASH_PREFIX):
            return hmac.compare_digest(Hashing._long_value_hash(plain_password), hashed_password)
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def verify_hash(plain_value: str, hashed_value: str) -> bool:
        """Verify a plain value against its hash (for token hashing)."""
        if hashed_value.startswith(LONG_VALUE_HASH_PREFIX):
            return hmac.compare_digest(Hashing._long_value_hash(plain_value), hashed_value)
        return pwd_context.verify(plain_value, hashed_value)


# if __name__ == "__main__":
#     print(Hashing.create_hash(""))
