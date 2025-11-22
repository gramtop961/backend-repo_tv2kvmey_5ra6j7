import os
from datetime import datetime, timedelta, timezone, date
from typing import List, Optional, Literal

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db

# Environment & Security setup
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="School Management System API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------- Utility Functions -----------------------

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ----------------------- Schemas -----------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=6)
    role: Literal["admin", "teacher", "student", "parent"] = "student"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class PublicUser(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    avatar_url: Optional[str] = None


class CreateStudent(BaseModel):
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    gender: Optional[Literal["male", "female", "other"]] = None
    dob: Optional[date] = None
    grade: Optional[str] = None
    roll_number: Optional[str] = None
    address: Optional[str] = None
    guardian_name: Optional[str] = None
    guardian_contact: Optional[str] = None
    admission_date: Optional[date] = None


class UpdateStudent(CreateStudent):
    pass


# ----------------------- Auth Helpers -----------------------
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = None
    if db is not None:
        try:
            user = db["user"].find_one({"_id": ObjectId(user_id)})
        except Exception:
            email = payload.get("email")
            if email:
                user = db["user"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["id"] = str(user.get("_id"))
    return user


# ----------------------- Health -----------------------
@app.get("/")
def read_root():
    return {"message": "School Management System API running"}


@app.get("/health")
def health():
    return {"ok": True, "time": datetime.now(timezone.utc).isoformat()}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = getattr(db, 'name', 'unknown')
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# ----------------------- Auth Endpoints -----------------------
@app.post("/auth/register", response_model=PublicUser)
def register(req: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    existing = db["user"].find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = {
        "name": req.name,
        "email": str(req.email),
        "password_hash": get_password_hash(req.password),
        "role": req.role,
        "avatar_url": None,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(doc)
    return PublicUser(id=str(res.inserted_id), name=req.name, email=req.email, role=req.role)


@app.post("/auth/login", response_model=Token)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["user"].find_one({"email": str(payload.email)})
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": str(user["_id"]), "email": user["email"], "role": user.get("role", "student")})
    return Token(access_token=token)


# ----------------------- Student Endpoints -----------------------
@app.post("/students")
def create_student(student: CreateStudent, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if current.get("role") not in ["admin", "teacher"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    data = student.model_dump()
    data.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = db["student"].insert_one(data)
    return {"id": str(res.inserted_id), **student.model_dump()}


@app.get("/students")
def list_students(q: Optional[str] = None, limit: int = 100, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    query = {}
    if q:
        query = {"$or": [
            {"first_name": {"$regex": q, "$options": "i"}},
            {"last_name": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
        ]}
    docs = db["student"].find(query).limit(limit)
    items = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        items.append(d)
    return {"items": items}


@app.get("/students/{student_id}")
def get_student(student_id: str, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    try:
        oid = ObjectId(student_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    doc = db["student"].find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["id"] = str(doc.pop("_id"))
    return doc


@app.put("/students/{student_id}")
def update_student(student_id: str, payload: UpdateStudent, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if current.get("role") not in ["admin", "teacher"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        oid = ObjectId(student_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    data["updated_at"] = datetime.now(timezone.utc)
    res = db["student"].update_one({"_id": oid}, {"$set": data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "ok"}


@app.delete("/students/{student_id}")
def delete_student(student_id: str, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if current.get("role") not in ["admin", "teacher"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        oid = ObjectId(student_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    res = db["student"].delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "deleted"}


# ----------------------- Attendance -----------------------
class AttendanceRecordIn(BaseModel):
    student_id: str
    status: Literal["present", "absent", "late"] = "present"
    note: Optional[str] = None


class TakeAttendanceIn(BaseModel):
    class_id: Optional[str] = None
    date: date
    records: List[AttendanceRecordIn]


@app.post("/attendance")
def take_attendance(payload: TakeAttendanceIn, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if current.get("role") not in ["admin", "teacher"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    doc = {
        "class_id": payload.class_id,
        "date": payload.date.isoformat(),
        "taken_by": str(current.get("_id", "")),
        "records": [r.model_dump() for r in payload.records],
        "created_at": datetime.now(timezone.utc),
    }
    res = db["attendance"].insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/attendance")
def list_attendance(date_str: Optional[str] = None, limit: int = 50, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    query = {}
    if date_str:
        query["date"] = date_str
    docs = db["attendance"].find(query).limit(limit)
    items = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        items.append(d)
    return {"items": items}


# ----------------------- Announcements -----------------------
class AnnouncementIn(BaseModel):
    title: str
    message: str


@app.post("/announcements")
def create_announcement(payload: AnnouncementIn, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if current.get("role") not in ["admin", "teacher"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    doc = {
        "title": payload.title,
        "message": payload.message,
        "created_by": str(current.get("_id", "")),
        "created_at": datetime.now(timezone.utc),
    }
    res = db["announcement"].insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/announcements")
def list_announcements(limit: int = 20, current=Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    docs = db["announcement"].find({}).sort("created_at", -1).limit(limit)
    items = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        items.append(d)
    return {"items": items}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
