"""
Database Schemas for School Management System (MongoDB via Pydantic models)
Each Pydantic model represents a collection; collection name is the lowercase of class name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import date, datetime

# Core Users
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr
    password_hash: str = Field(..., description="Password hash with salt")
    role: Literal["admin", "teacher", "student", "parent"] = "student"
    avatar_url: Optional[str] = None
    is_active: bool = True

class Student(BaseModel):
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

class ClassRoom(BaseModel):
    name: str = Field(..., description="Class/Section name e.g. 7A")
    grade: Optional[str] = None
    teacher_id: Optional[str] = None  # reference to user _id
    subject_ids: Optional[List[str]] = None

class Subject(BaseModel):
    name: str
    code: Optional[str] = None
    description: Optional[str] = None

class AttendanceRecord(BaseModel):
    student_id: str
    status: Literal["present", "absent", "late"] = "present"
    note: Optional[str] = None

class Attendance(BaseModel):
    class_id: str
    date: date
    taken_by: str  # user id
    records: List[AttendanceRecord]

# Minimal additional placeholders (extend later)
class Announcement(BaseModel):
    title: str
    message: str
    created_by: str
    created_at: Optional[datetime] = None
