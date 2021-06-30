import datetime
from os import EX_PROTOCOL
from fastapi import FastAPI, HTTPException, Depends, Request, exceptions
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel

from datetime import datetime, timedelta


class User(BaseModel):
    username: str
    password: str


class Settings(BaseModel):
    authjwt_secret_key: str = 'secret'


@AuthJWT.load_config
def get_config():
    return Settings()


app = FastAPI()


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    print(request.headers)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.message
        }
    )


@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401, detail="Unauthorize")

    access_expires = timedelta(seconds=60)
    refresh_expires = timedelta(seconds=300)
    another_claims = {
        "foo": ["bar", "fize"],
        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }
    access_token = Authorize.create_access_token(
        subject=user.username, expires_time=access_expires, user_claims=another_claims)
    refresh_token = Authorize.create_refresh_token(
        subject=user.username, expires_time=refresh_expires)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


@app.post('/refresh')
def refresh(Authorize: AuthJWT = Depends()):
    '''
        POST with refresh token in header 
        { authorization: Bearer refresh_token } for renew access token
    '''
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_subject()
    access_expires = timedelta(seconds=60)
    refresh_expires = timedelta(seconds=300)

    new_access_token = Authorize.create_access_token(
        subject=current_user, expires_time=access_expires)
    new_refresh_token = Authorize.create_access_token(
        subject=current_user, expires_time=refresh_expires)
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }


@app.get('/user')
def user(Authorize: AuthJWT = Depends()):
    '''
    Authorization with access token
    '''
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    return {
        "user": current_user,
        "raw_jwt": Authorize.get_raw_jwt()
    }
