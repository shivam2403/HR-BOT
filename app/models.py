from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    responses = db.relationship('CandidateResponse', backref='candidate', lazy=True)

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
