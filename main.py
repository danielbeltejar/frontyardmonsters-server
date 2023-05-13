import os
import secrets

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from pymongo import MongoClient
from passlib.context import CryptContext
from bson.objectid import ObjectId
from jose import JWTError, jwt
from dotenv import load_dotenv

app = FastAPI()
load_dotenv()

client = MongoClient("mongodb://" + os.environ.get("MONGO_HOST") + "/")
db = client[os.environ.get("MONGO_DATABASE")]
users_collection = db[os.environ.get("MONGO_COLLECTION")]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/account/token")

SECRET_KEY = os.environ.get('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES')
ENABLED_REGISTRATION = bool(os.environ.get('ENABLED_REGISTRATION'))
ENABLED_LOGIN = bool(os.environ.get('ENABLED_LOGIN'))


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def verify_token(local_token: str, stored_token: str):
    return True if local_token == stored_token else False


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str, login_token: str = None):
    user = users_collection.find_one({"username": username})
    if not user:
        return False
    if login_token is not None:
        if verify_token(login_token, user["login_token"]):
            return True
        elif verify_password(password, user["password"]):
            ##TODO add new token to the database and local storage
            return True
    if not verify_password(password, user["password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/account/register")
async def register(request: Request):
    if not ENABLED_REGISTRATION:
        return {"message": "New users registers disabled",
                "code": 0}
    data = await request.json()

    auth_token = secrets.token_hex(32)
    hashed_password = get_password_hash(data["password"])
    user = {"username": str(data["username"]),
            "password": str(hashed_password),
            "auth_token": auth_token,
            "is_active": True}
    users_collection.insert_one(user)

    return {"message": "User created successfully",
            "auth_token": auth_token}


@app.post("/account/login")
async def login(request: Request):
    if not ENABLED_LOGIN:
        return {"message": "Login  disabled",
                "code": 1}
    data = await request.json()

    user = authenticate_user(data["username"], data["password"], data["auth_token"])

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"auth_token": data["auth_token"]}
