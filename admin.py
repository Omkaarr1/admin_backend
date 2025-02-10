import os
import io
import json
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Generator

from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Boolean, ARRAY
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from sqlalchemy.pool import NullPool

from passlib.context import CryptContext
from jose import JWTError, jwt

# ----------------------------
# Database configuration
# ----------------------------
DATABASE_URL = "postgresql://postgres.axjmmpnxmurczteqwmka:%40Omkargupta123@aws-0-ap-south-1.pooler.supabase.com:5432/postgres"
IST = timezone(timedelta(hours=5, minutes=30))

engine = create_engine(DATABASE_URL, echo=False, poolclass=NullPool)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# ----------------------------
# Models
# ----------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, unique=True)
    name = Column(String(100), nullable=False)
    role = Column(String(50), default="NONE")  # Admin users have role 'admin'
    hashed_password = Column(String(255), nullable=False)

class RequestModel(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    initiator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    supervisor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    area = Column(String(50), nullable=False)
    project = Column(String(50), nullable=False)
    tower = Column(String(50), nullable=False)
    department = Column(String(50), nullable=False)
    priority = Column(String(20), nullable=False)
    file_url = Column(String(1024), nullable=True)
    file_display_name = Column(String(255), nullable=True)
    approvers = Column(ARRAY(Integer), nullable=False)
    current_approver_index = Column(Integer, default=0)
    status = Column(String(50), default="NEW")
    created_at = Column(DateTime, default=lambda: datetime.now(IST))
    updated_at = Column(DateTime, default=lambda: datetime.now(IST), onupdate=lambda: datetime.now(IST))
    last_action = Column(Text, nullable=True)
    supervisor_approved_at = Column(DateTime, nullable=True)
    supervisor_approved = Column(Boolean, nullable=True)
    supervisor_comment = Column(Text, nullable=True)
    
    initiator = relationship("User", foreign_keys=[initiator_id])
    supervisor = relationship("User", foreign_keys=[supervisor_id])
    approver_actions = relationship("ApproverAction", back_populates="request", cascade="all, delete-orphan")

class ApproverAction(Base):
    __tablename__ = "approver_actions"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), nullable=False)
    approver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved = Column(String(10), nullable=True)
    action_time = Column(DateTime, nullable=True)
    received_at = Column(DateTime, nullable=True)
    comment = Column(Text, nullable=True)
    
    request = relationship("RequestModel", back_populates="approver_actions")
    approver = relationship("User")

# Create tables in the database
Base.metadata.create_all(bind=engine)

# ----------------------------
# Security & Utility Functions
# ----------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

SECRET_KEY = os.getenv("SECRET_KEY", "my-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ----------------------------
# FastAPI Application Setup
# ----------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_FOLDER = "/tmp/nfa_files"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ----------------------------
# Dependency for Database Session
# ----------------------------
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()  # db is of type Session
    try:
        yield db
    finally:
        db.close()

# ----------------------------
# Admin Authentication Dependency
# ----------------------------
security = HTTPBearer()

def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_id = payload.get("sub")
        if admin_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is invalid")
    admin = db.query(User).filter(User.id == int(admin_id)).first()
    if admin is None or admin.role.lower() != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    return admin

# ----------------------------
# Admin Authentication Endpoint
# ----------------------------
@app.post("/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if not username or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password required")
    admin = db.query(User).filter(User.username == username).first()
    if not admin or not verify_password(password, admin.hashed_password) or admin.role.lower() != "admin":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials for admin")
    access_token = create_access_token({"sub": str(admin.id)})
    return {"access_token": access_token, "token_type": "bearer"}

# ----------------------------
# User Management Endpoints
# ----------------------------
@app.post("/admin/users")
def create_user(
    data: dict = Body(...),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    username = data.get("username")
    name = data.get("name")
    role = data.get("role")
    password = data.get("password")
    if not all([username, name, role, password]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing fields")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    new_user = User(
        username=username,
        name=name,
        role=role,
        hashed_password=get_password_hash(password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {
        "id": new_user.id,
        "username": new_user.username,
        "name": new_user.name,
        "role": new_user.role
    }

@app.get("/admin/users")
def list_users(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return [{
        "id": u.id,
        "username": u.username,
        "name": u.name,
        "role": u.role
    } for u in users]

@app.get("/admin/users/{user_id}")
def get_user(
    user_id: int,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "role": user.role
    }

@app.put("/admin/users/{user_id}")
def update_user(
    user_id: int,
    data: dict = Body(...),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if "username" in data:
        user.username = data["username"]
    if "name" in data:
        user.name = data["name"]
    if "role" in data:
        user.role = data["role"]
    if "password" in data:
        user.hashed_password = get_password_hash(data["password"])
    db.commit()
    db.refresh(user)
    return {
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "role": user.role
    }

@app.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(user)
    db.commit()
    return {"detail": "User deleted"}

# ----------------------------
# Request Management Endpoints
# ----------------------------
@app.get("/admin/requests")
def list_requests(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    requests_list = db.query(RequestModel).all()
    result = []
    for r in requests_list:
        result.append({
            "id": r.id,
            "initiator_id": r.initiator_id,
            "supervisor_id": r.supervisor_id,
            "subject": r.subject,
            "description": r.description,
            "area": r.area,
            "project": r.project,
            "tower": r.tower,
            "department": r.department,
            "priority": r.priority,
            "file_url": r.file_url,
            "file_display_name": r.file_display_name,
            "approvers": r.approvers,
            "current_approver_index": r.current_approver_index,
            "status": r.status,
            "created_at": r.created_at.strftime("%d-%m-%Y %H:%M"),
            "updated_at": r.updated_at.strftime("%d-%m-%Y %H:%M"),
            "last_action": r.last_action
        })
    return result

@app.get("/admin/requests/{request_id}")
def get_request(
    request_id: int,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    r = db.query(RequestModel).filter(RequestModel.id == request_id).first()
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    return {
        "id": r.id,
        "initiator_id": r.initiator_id,
        "supervisor_id": r.supervisor_id,
        "subject": r.subject,
        "description": r.description,
        "area": r.area,
        "project": r.project,
        "tower": r.tower,
        "department": r.department,
        "priority": r.priority,
        "file_url": r.file_url,
        "file_display_name": r.file_display_name,
        "approvers": r.approvers,
        "current_approver_index": r.current_approver_index,
        "status": r.status,
        "created_at": r.created_at.strftime("%d-%m-%Y %H:%M"),
        "updated_at": r.updated_at.strftime("%d-%m-%Y %H:%M"),
        "last_action": r.last_action
    }

@app.put("/admin/requests/{request_id}")
def update_request(
    request_id: int,
    data: dict = Body(...),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    r = db.query(RequestModel).filter(RequestModel.id == request_id).first()
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    if "subject" in data:
        r.subject = data["subject"]
    if "description" in data:
        r.description = data["description"]
    if "area" in data:
        r.area = data["area"]
    if "project" in data:
        r.project = data["project"]
    if "tower" in data:
        r.tower = data["tower"]
    if "department" in data:
        r.department = data["department"]
    if "priority" in data:
        r.priority = data["priority"]
    if "status" in data:
        r.status = data["status"]
    db.commit()
    db.refresh(r)
    return {
        "id": r.id,
        "initiator_id": r.initiator_id,
        "supervisor_id": r.supervisor_id,
        "subject": r.subject,
        "description": r.description,
        "area": r.area,
        "project": r.project,
        "tower": r.tower,
        "department": r.department,
        "priority": r.priority,
        "file_url": r.file_url,
        "file_display_name": r.file_display_name,
        "approvers": r.approvers,
        "current_approver_index": r.current_approver_index,
        "status": r.status,
        "created_at": r.created_at.strftime("%d-%m-%Y %H:%M"),
        "updated_at": r.updated_at.strftime("%d-%m-%Y %H:%M"),
        "last_action": r.last_action
    }

@app.delete("/admin/requests/{request_id}")
def delete_request(
    request_id: int,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    r = db.query(RequestModel).filter(RequestModel.id == request_id).first()
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    db.delete(r)
    db.commit()
    return {"detail": "Request deleted"}

@app.post("/admin/requests/{request_id}/approve")
def approve_request(
    request_id: int,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    r = db.query(RequestModel).filter(RequestModel.id == request_id).first()
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    r.status = "APPROVED"
    r.last_action = f"Admin {current_admin.name} approved the request at {datetime.now(IST).strftime('%d-%m-%Y %H:%M')}"
    db.commit()
    db.refresh(r)
    return {
        "id": r.id,
        "initiator_id": r.initiator_id,
        "supervisor_id": r.supervisor_id,
        "subject": r.subject,
        "description": r.description,
        "area": r.area,
        "project": r.project,
        "tower": r.tower,
        "department": r.department,
        "priority": r.priority,
        "file_url": r.file_url,
        "file_display_name": r.file_display_name,
        "approvers": r.approvers,
        "current_approver_index": r.current_approver_index,
        "status": r.status,
        "created_at": r.created_at.strftime("%d-%m-%Y %H:%M"),
        "updated_at": r.updated_at.strftime("%d-%m-%Y %H:%M"),
        "last_action": r.last_action
    }

@app.post("/admin/requests/{request_id}/reject")
def reject_request(
    request_id: int,
    comment: Optional[str] = Form(None),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    r = db.query(RequestModel).filter(RequestModel.id == request_id).first()
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    r.status = "REJECTED"
    r.last_action = f"Admin {current_admin.name} rejected the request at {datetime.now(IST).strftime('%d-%m-%Y %H:%M')}" + (f" Comment: {comment}" if comment else "")
    db.commit()
    db.refresh(r)
    return {
        "id": r.id,
        "initiator_id": r.initiator_id,
        "supervisor_id": r.supervisor_id,
        "subject": r.subject,
        "description": r.description,
        "area": r.area,
        "project": r.project,
        "tower": r.tower,
        "department": r.department,
        "priority": r.priority,
        "file_url": r.file_url,
        "file_display_name": r.file_display_name,
        "approvers": r.approvers,
        "current_approver_index": r.current_approver_index,
        "status": r.status,
        "created_at": r.created_at.strftime("%d-%m-%Y %H:%M"),
        "updated_at": r.updated_at.strftime("%d-%m-%Y %H:%M"),
        "last_action": r.last_action
    }

@app.get("/")
def index():
    return {"message": "Admin backend is running"}

# ----------------------------
# Entry Point
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
