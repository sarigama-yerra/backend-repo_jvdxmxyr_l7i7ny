import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import JWTError, jwt

from database import db

app = FastAPI(title="PixelPicks API", version="1.0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# tokenUrl is used for OpenAPI docs only
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ----- Pydantic models -----
class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    is_active: bool

# ----- Helpers -----

def get_user_collection() -> "pymongo.collection.Collection":
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db["authuser"]


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_user_by_email(email: str) -> Optional[dict]:
    return get_user_collection().find_one({"email": email.lower()})


def get_user_by_id(user_id: str) -> Optional[dict]:
    from bson import ObjectId
    try:
        return get_user_collection().find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


def user_doc_to_public(doc: dict) -> UserPublic:
    return UserPublic(
        id=str(doc.get("_id")),
        name=doc.get("name"),
        email=doc.get("email"),
        is_active=bool(doc.get("is_active", True)),
    )


# Lightweight manual bearer auth (no OAuth2 form dependency to avoid Pydantic/Param conflicts)
from fastapi import Header
async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


# ----- Routes -----
@app.get("/")
def read_root():
    return {"message": "PixelPicks backend is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set",
        "database_name": "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:80]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


@app.post("/auth/register", response_model=UserPublic, status_code=201)
def register(payload: RegisterRequest):
    coll = get_user_collection()
    email = payload.email.lower()

    if coll.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Email already registered")

    doc = {
        "name": payload.name.strip(),
        "email": email,
        "password_hash": hash_password(payload.password),
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    result = coll.insert_one(doc)
    doc["_id"] = result.inserted_id
    try:
        coll.create_index("email", unique=True)
    except Exception:
        pass
    return user_doc_to_public(doc)


# JSON-based login (avoids form parsing and related dependency issues)
@app.post("/auth/login-json", response_model=TokenResponse)
def login_json(payload: LoginRequest):
    user = get_user_by_email(payload.email.lower())
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=access_token)


@app.get("/auth/me", response_model=UserPublic)
async def me(current_user: dict = Depends(get_current_user)):
    return user_doc_to_public(current_user)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
