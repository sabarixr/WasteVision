# main.py
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, File, Form, UploadFile
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, validator

from sqlmodel import Field, SQLModel, create_engine, Session, select
from google.cloud import storage

# ---------------- CONFIG ----------------
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 1 day
UPLOAD_BUCKET = os.environ.get("UPLOAD_BUCKET")
SIGNED_URL_EXPIRATION = 300  # seconds
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
# ----------------------------------------

# Use a more compatible bcrypt configuration that handles version issues
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # Test if bcrypt works
    pwd_context.hash("test")
except Exception as e:
    print(f"[WARNING] bcrypt not working ({e}), falling back to pbkdf2_sha256")
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

app = FastAPI()

# serve static folder
app.mount("/static", StaticFiles(directory="static"), name="static")

# DB engine
engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

# Dev mode: fall back to fake storage if Google Cloud credentials not available
def create_storage_client():
    try:
        # Only try real client if we have explicit bucket config
        if os.environ.get("UPLOAD_BUCKET") and os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            return storage.Client()
        elif os.environ.get("UPLOAD_BUCKET"):
            # Try default credentials, but fail fast
            return storage.Client()
    except Exception as e:
        pass
    
    # Fake storage client for local development/testing
    class LocalBlob:
        def __init__(self, name):
            self.name = name
            self._data = None
            
        def upload_from_string(self, data, content_type=None):
            # In dev mode, just store in memory (or could save to local file)
            self._data = data
            print(f"[DEV] Fake upload: {self.name} ({len(data)} bytes)")
            
        def generate_signed_url(self, expiration):
            # Return a fake URL for dev mode
            return f"https://fake-storage.dev/{self.name}?expires={expiration}"
    
    class LocalBucket:
        def __init__(self, name):
            self.name = name
            
        def blob(self, name):
            return LocalBlob(name)
    
    class LocalStorageClient:
        def bucket(self, name):
            return LocalBucket(name)
    
    print(f"[DEV] Using fake storage client (Google Cloud not configured for dev)")
    return LocalStorageClient()

storage_client = create_storage_client()

# ---------------- MODELS ----------------

class User(SQLModel, table=True):
    __table_args__ = {'extend_existing': True}
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: str = Field(default="user")


class Report(SQLModel, table=True):
    __table_args__ = {'extend_existing': True}
    id: Optional[int] = Field(default=None, primary_key=True)
    filename: str
    uploader_id: int
    lat: Optional[float] = None
    lon: Optional[float] = None
    timestamp: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    immediate_attention: Optional[bool] = None
    notes: Optional[str] = None


# Create DB
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

create_db_and_tables()


# ---------------- AUTH HELPERS ----------------

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def hash_password(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    cred_exc = HTTPException(status_code=401, detail="Invalid token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise cred_exc
    except JWTError:
        raise cred_exc

    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == username)).first()
        if not user:
            raise cred_exc
        return user


def require_authority(user: User = Depends(get_current_user)):
    if user.role != "authority":
        raise HTTPException(403, "Authority only.")
    return user


# ---------------- SCHEMAS ----------------

class UserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "user"

    @validator("password")
    def validate_password(cls, v: str) -> str:
        if v is None:
            raise ValueError("password is required")
        try:
            b = v.encode("utf-8")
        except Exception:
            # fallback: if encoding fails for some reason
            raise ValueError("password must be a valid UTF-8 string")

        if len(b) > 72:
            raise ValueError(
                "password cannot be longer than 72 bytes, truncate manually if necessary (e.g. my_password[:72])"
            )
        return v


class Token(BaseModel):
    access_token: str
    token_type: str


class ReportOut(BaseModel):
    id: int
    filename: str
    image_url: Optional[str]
    uploader_id: int
    lat: Optional[float]
    lon: Optional[float]
    timestamp: Optional[datetime]
    created_at: datetime
    immediate_attention: Optional[bool]
    notes: Optional[str]


# ---------------- API ROUTES ----------------

@app.post("/api/signup")
def signup(data: UserCreate):
    try:
        username = data.username.strip()
        password = data.password
        role = data.role or "user"

        if role not in ["user", "authority"]:
            raise HTTPException(400, "Invalid role")

        with Session(engine) as session:
            existing = session.exec(select(User).where(User.username == username)).first()
            if existing:
                raise HTTPException(400, "Username already exists")

            new_user = User(
                username=username,
                hashed_password=hash_password(password),
                role=role
            )
            session.add(new_user)
            session.commit()

        return {"message": "User created"}

    except HTTPException:
        # Re-raise HTTP exceptions without wrapping them
        raise
    except ValueError as e:
        # If it's a validation/value error (e.g. password too long), return 400
        raise HTTPException(status_code=400, detail=f"Signup failed: {str(e)}")
    except Exception as e:
        raise HTTPException(500, f"Signup failed: {str(e)}")


@app.post("/api/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == form.username)).first()
        if not user or not verify_password(form.password, user.hashed_password):
            raise HTTPException(401, "Incorrect username or password")

        token = create_access_token({"sub": user.username})
        return {"access_token": token, "token_type": "bearer"}


@app.post("/api/report", response_model=ReportOut)
async def create_report(
    image: UploadFile = File(...),
    lat: Optional[float] = Form(None),
    lon: Optional[float] = Form(None),
    timestamp: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    user: User = Depends(get_current_user)
):
    if not UPLOAD_BUCKET:
        raise HTTPException(500, "UPLOAD_BUCKET missing")

    filename = f"uploads/{uuid.uuid4().hex}_{image.filename}"
    data = await image.read()

    bucket = storage_client.bucket(UPLOAD_BUCKET)
    blob = bucket.blob(filename)
    blob.upload_from_string(data, content_type=image.content_type)

    ts = None
    if timestamp:
        try:
            ts = datetime.fromisoformat(timestamp)
        except Exception:
            ts = None

    with Session(engine) as session:
        report = Report(
            filename=filename,
            uploader_id=user.id,
            lat=lat,
            lon=lon,
            timestamp=ts,
            notes=notes,
            immediate_attention=None
        )
        session.add(report)
        session.commit()
        session.refresh(report)

    url = blob.generate_signed_url(expiration=timedelta(seconds=SIGNED_URL_EXPIRATION))

    return ReportOut(
        id=report.id,
        filename=report.filename,
        image_url=url,
        uploader_id=report.uploader_id,
        lat=report.lat,
        lon=report.lon,
        timestamp=report.timestamp,
        created_at=report.created_at,
        immediate_attention=report.immediate_attention,
        notes=report.notes
    )


@app.get("/api/reports", response_model=List[ReportOut])
def list_reports(user: User = Depends(get_current_user)):
    with Session(engine) as session:
        if user.role == "authority":
            reports = session.exec(select(Report).order_by(Report.created_at.desc())).all()
        else:
            reports = session.exec(
                select(Report)
                .where(Report.uploader_id == user.id)
                .order_by(Report.created_at.desc())
            ).all()

    bucket = storage_client.bucket(UPLOAD_BUCKET)
    results = []

    for r in reports:
        url = bucket.blob(r.filename).generate_signed_url(
            expiration=timedelta(seconds=SIGNED_URL_EXPIRATION)
        )
        results.append(ReportOut(
            id=r.id,
            filename=r.filename,
            image_url=url,
            uploader_id=r.uploader_id,
            lat=r.lat,
            lon=r.lon,
            timestamp=r.timestamp,
            created_at=r.created_at,
            immediate_attention=r.immediate_attention,
            notes=r.notes
        ))

    return results


@app.post("/api/reports/{report_id}/action")
def modify_report(
    report_id: int,
    immediate_attention: Optional[bool] = None,
    notes: Optional[str] = None,
    auth: User = Depends(require_authority)
):
    with Session(engine) as session:
        r = session.get(Report, report_id)
        if not r:
            raise HTTPException(404, "Report not found")

        if immediate_attention is not None:
            r.immediate_attention = immediate_attention

        if notes:
            r.notes = notes

        session.add(r)
        session.commit()

    return {"message": "updated"}


# ---------------- ROOT ROUTE ----------------

@app.get("/")
def root():
    return FileResponse("static/signup.html")


# ---------------- DEV SERVER ----------------

if __name__ == "__main__":
    import uvicorn
    print("Starting FastAPI development server...")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
