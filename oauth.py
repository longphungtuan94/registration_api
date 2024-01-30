from datetime import datetime, timedelta, timezone
from typing import Annotated, Union

from fastapi import Depends, FastAPI, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from loguru import logger
from utils import pwd_context
from config.env_config import *

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Union[str, None] = None


class UserCreate(BaseModel):
    email: str
    password: str


class UserInDB(BaseModel):
    email: str
    hashed_password: str
    disabled: bool


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


async def get_user(email: str):
    users_collection = db[MONGODB_COLLECTION_NAME]
    existing_user = await users_collection.find_one({"email": email})
    if existing_user:
        return existing_user
    else:
        return False


# Function to create a new user
async def create_user(db: AsyncIOMotorDatabase, user: UserCreate):
    users_collection = db[MONGODB_COLLECTION_NAME]
    existing_user = await get_user(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="E-mail already exists")

    hashed_password = pwd_context.get_password_hash(user.password)
    new_user = UserInDB(**user.dict(exclude={"password"}), disabled=False, hashed_password=hashed_password)
    await users_collection.insert_one(new_user.dict())
    return {"detail": "Registration successful"}


async def authenticate_user(email: str, password: str):
    users_collection = db[MONGODB_COLLECTION_NAME]
    user = await get_user(email)
    if not user:
        return False
    if not pwd_context.verify_password(password, user['hashed_password']):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[UserInDB, Depends(get_current_user)]
):
    if current_user['disabled']:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.on_event("startup")
async def startup_db_client():
    global db, db_client
    db_client = AsyncIOMotorClient(MONGODB_URL)
    db = db_client[MONGODB_DB_NAME]


@app.on_event("shutdown")
async def shutdown_db_client():
    db_client.close()


@app.get("/", status_code=status.HTTP_200_OK)
async def health_check():
    return {"App status": "OK"}


@app.get("/email/{email}", status_code=status.HTTP_200_OK)
async def check_email(email: str, response: Response):
    users_collection = db[MONGODB_COLLECTION_NAME]

    existing_user = await users_collection.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="E-mail already exists")
    else:
        return {"detail": "E-mail is available"}


@app.post("/register/", status_code=status.HTTP_200_OK)
async def register(user: UserCreate):
    return await create_user(db, user)


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me")
async def read_own_info(
    current_user: Annotated[UserInDB, Depends(get_current_active_user)]
):
    return [{"owner": current_user['email']}]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=3000)