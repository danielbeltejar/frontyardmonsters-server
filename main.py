from starlette.middleware.cors import CORSMiddleware

from endpoints import Account  # Import the Account module

from fastapi import FastAPI, APIRouter
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from dotenv import load_dotenv

from websocket import ServerProtocol

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["DELETE", "GET", "POST", "PUT"],
    allow_headers=["*"],
)

app.include_router(Account.router, prefix="/account")  # Include the account routes
app.include_router(ServerProtocol.router, prefix="/ws")  # Include the account routes

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/account/token")


@app.on_event("startup")
async def startup():
    pass
    # await database.connect()


@app.on_event("shutdown")
async def shutdown():
    pass
    # await database.disconnect()


if __name__ == '__main__':
    pass
