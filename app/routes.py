from flask import Blueprint, jsonify, request, render_template
from app.models import db, Candidate, Question, HRInput, CandidateResponse
import openai
import json
import re
from flask import Blueprint

routes_blueprint = Blueprint('routes', __name__)
@routes_blueprint.route('/hr')
def index():
    return render_template('hr.html')


@routes_blueprint.route('/')
def home():
    return render_template('index.html')


@routes_blueprint.route('/save_hr_input_and_generate_questions', methods=['POST'])
def save_hr_input_and_generate_questions():
    data = request.json

    job_description = data.get('jobDescription')
    key_skills = data.get('keySkills')
    job_role = data.get('jobRole')
    required_experience = data.get('requiredExperience')

    new_hr_input = HRInput(
        job_description=job_description,
        key_skills=key_skills,
        job_role=job_role,
        required_experience=required_experience
    )

    db.session.add(new_hr_input)
    db.session.commit()

    generated_questions = generate_hr_questions(job_role)

    for question_content in extract_questions(generated_questions):
        new_question = Question(content=question_content, job_role=job_role)
        db.session.add(new_question)
        db.session.commit()

    return jsonify({'message': 'HR inputs and questions saved successfully'})


def generate_hr_questions(role):
    test_message = [
        {"role": "system", "content": "HR Interview Bot generates role-specific questions."},
        {"role": "user", "content": f"Generate questions for {role} role assume you are HR"}
    ]

    complete = openai.ChatCompletion.create(
        model="ft:gpt-3.5-turbo-0613:funnelhq::8XO5lEhK",
        temperature=1,
        max_tokens=300,
        messages=test_message
    )

    return complete['choices'][0]['message']['content']


def extract_questions(generated_questions):
    return [q.strip() for q in re.split(r'\n\s*\d+\.\s*', generated_questions) if q.strip()]


@routes_blueprint.route('/save_questions/<job_role>', methods=['POST'])
def save_questions(job_role):
    generated_questions = generate_hr_questions(job_role)

    for question_content in extract_questions(generated_questions):
        new_question = Question(content=question_content, job_role=job_role)
        db.session.add(new_question)
        db.session.commit()

    return jsonify({'message': f'Questions for {job_role} role saved successfully'})


@routes_blueprint.route('/get_question/<job_role>', methods=['GET'])
def get_question(job_role):
    question_id = int(request.args.get('question_id', 1))

    
    questions = Question.query.filter_by(job_role=job_role).all()

    if questions:
        
        if 0 < question_id <= len(questions):
            question = questions[question_id - 1]  
            return jsonify({'question_id': question_id, 'question': question.content})
        else:
            return jsonify({'message': 'No more questions available for this job role'})
    else:
        return jsonify({'message': 'No questions available for this job role'})
    
@routes_blueprint.route('/submit_response', methods=['POST'])
def submit_response():
    data = request.json
    candidate_name = data.get('candidate_name')
    question_id = data.get('question_id')
    response = data.get('response')

    
    candidate = Candidate.query.filter_by(name=candidate_name).first()
    if not candidate:
        candidate = Candidate(name=candidate_name)
        db.session.add(candidate)
        db.session.commit()

    
    question = Question.query.get(question_id)
    if not question:
        return jsonify({'message': 'Question not found'}), 404

    
    existing_response = CandidateResponse.query.filter_by(
        candidate_id=candidate.id, question_id=question_id).first()
    if existing_response:
        return jsonify({'message': 'Response already exists for this candidate and question'})

    
    new_response = CandidateResponse(
        candidate_id=candidate.id,
        question_id=question_id,
        response=response
    )

    db.session.add(new_response)
    db.session.commit()

    return jsonify({'message': 'Candidate response saved successfully'})


def find_best_fit_candidates(job_role):
    system_message = "HR Interview Bot analyzes best-fit candidates based on their responses for job matching."

    
    hr_input = HRInput.query.filter_by(job_role=job_role).first()

    if not hr_input:
        return jsonify({'error': 'No HR input found for this role'}), 404

    key_skills = hr_input.key_skills
    years_experience = hr_input.required_experience

    user_message = {
        "job_title": job_role,
        "key_skills": key_skills,
        "years_experience": years_experience
    }

    
    candidate_responses = CandidateResponse.query.join(Question).filter(
        Question.job_role == job_role
    ).all()

    assistant_message = {
        "candidates": [
            {
                "candidate_id": response.candidate_id,
                "question": response.question.content,
                "response": response.response
            }
            for response in candidate_responses
        ]
    }

    data = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": json.dumps(user_message)},
        {"role": "assistant", "content": json.dumps(assistant_message)}
    ]

    model_response = openai.ChatCompletion.create(
        model="ft:gpt-3.5-turbo-0613:funnelhq::8c5QTXcf",
        messages=data,
        temperature=1,
        max_tokens=2000
    )

    best_fit_candidates = model_response['choices'][0]['message']['content']
    return best_fit_candidates

   

@routes_blueprint.route('/get_best_fit_candidates/<job_role>', methods=['GET'])
def get_best_fit_candidates(job_role):
    try:
        
        best_fit_candidates = find_best_fit_candidates(job_role)

        
        return jsonify({'Status':'success','Data': best_fit_candidates})

    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        return jsonify({'error': error_message}), 500
  



