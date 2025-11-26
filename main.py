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
from pydantic import BaseModel

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

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
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

storage_client = storage.Client()

# ---------------- MODELS ----------------

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: str = Field(default="user")


class Report(SQLModel, table=True):
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
        except:
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
