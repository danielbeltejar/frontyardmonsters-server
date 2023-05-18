import os
import secrets
import re

from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Body
from fastapi_limiter.depends import RateLimiter
from fastapi_utils.cbv import cbv
from passlib.context import CryptContext
from pymongo import MongoClient

router = APIRouter()
load_dotenv()

client = MongoClient("mongodb://" + os.environ.get("MONGO_HOST") + "/")
db = client[os.environ.get("MONGO_DATABASE")]
users_collection = db["accounts"]
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
SECRET_KEY = os.environ.get('SECRET_KEY')
ALGORITHM = "HS256"
ENABLED_REGISTRATION = bool(os.environ.get('ENABLED_REGISTRATION'))
ENABLED_LOGIN = bool(os.environ.get('ENABLED_LOGIN'))


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def verify_token(local_token: str, stored_token: str):
    return True if local_token == stored_token else False


def update_auth_token(username, auth_token):
    users_collection.update_one(
        {"username": username},
        {"$set": {"auth_token": auth_token}}
    )


def sanitize_username(username: str) -> str:
    # Remove any non-alphanumeric characters except underscore
    sanitized_username = re.sub(r"[^\w]+", "", username)

    # Truncate the username to a maximum length of 24 characters
    sanitized_username = sanitized_username[:24]

    return sanitized_username


def get_password_hash(password):
    return pwd_context.hash(password, scheme="argon2")


def authenticate_user(username: str, password: str, auth_token: str = None):
    user = users_collection.find_one({"username": username})
    if not user:
        return False

    if auth_token is not None and verify_token(auth_token, user["auth_token"]):
        return user

    if verify_password(password, user["password"]):
        auth_token = secrets.token_hex(16)
        user["auth_token"] = auth_token
        return user

    return False


@cbv(router)
class AuthViews:
    @router.post("/register")
    @RateLimiter(seconds=60, times=5)
    async def register(self, username: str = Body(...), password: str = Body(...)):
        if not ENABLED_REGISTRATION:
            raise HTTPException(status_code=400, detail="New users registration is disabled")

        # Sanitize and validate the username
        sanitized_username = sanitize_username(username)
        if not re.match(r"^\w{3,24}$", sanitized_username):
            raise HTTPException(status_code=400, detail="Invalid username")

        auth_token = secrets.token_hex(16)
        hashed_password = get_password_hash(str(password))
        user = {
            "username": str(sanitized_username),
            "password": str(hashed_password),
            "auth_token": auth_token,
            "is_active": True
        }
        users_collection.insert_one(user)

        return {"message": "User created successfully", "auth_token": auth_token, "username": str(sanitized_username)}

    @router.post("/login")
    @RateLimiter(seconds=60, times=5)
    async def login(self, username: str = Body(...), password: str = Body(default=None),
                    auth_token: str = Body(default=None)):
        if not ENABLED_LOGIN:
            raise HTTPException(status_code=400, detail="Login is disabled")

        user = authenticate_user(str(username), str(password), str(auth_token))
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect username or password")

        return {"auth_token": user["auth_token"], "username": str(username)}
