from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy.dialects.postgresql import ARRAY

db = SQLAlchemy()

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100),unique=True, nullable=False)
    phone = db.Column(db.String(10), unique=True)
    password = db.Column(db.String(60), nullable=False)
    google_user_id = db.Column(db.String(255), unique=True)
    responses = db.relationship('CandidateResponse', backref='candidate', lazy=True)
    resume_path = db.Column(db.String(255))
    skillset = db.Column(db.String(255))
    linkedin_url = db.Column(db.String(255))
    github_link = db.Column(db.String(255))
    twitter_link = db.Column(db.String(255))
    portfolio_link = db.Column(db.String(255))
    profile_picture_filename = db.Column(db.String(255))

    @validates('phone')
    def validate_phone(self, key, value):
        if not value.isdigit() or len(value) != 10:
            raise ValueError("Phone number must be exactly 10 digits.")
        return value

    def __repr__(self):
        return f"{self.id} - {self.username}"
    

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    job_role = db.Column(db.String(100), nullable=False)

class HRInput(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_description = db.Column(db.String(500), nullable=False)
    key_skills = db.Column(db.String(350), nullable=False)
    job_role = db.Column(db.String(100), nullable=False)
    required_experience = db.Column(db.String(100), nullable=False)

class CandidateResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    response = db.Column(db.String(500), nullable=False)
    question = db.relationship('Question', backref='responses')

    def __repr__(self):
        return f"<CandidateResponse {self.candidate.name} - {self.question.content}>"
