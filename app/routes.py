from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from .models import db, User, Candidate, Question, HRInput, CandidateResponse
import openai
import json
import re
from flask_mail import *
from .extensions import mail


routes_blueprint = Blueprint('routes', __name__)

@routes_blueprint.route('/')
def home():
    return redirect('/')

@routes_blueprint.route('/protected')
@login_required
def protected():
    return 'This is a protected route.'


@routes_blueprint.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')

            user = User.query.filter_by(email=email).first()

            if user and user.check_password(password):
                login_user(user)
                return jsonify({'message': 'Login successful', 'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'applied_job_role': user.applied_job_role,
                }, 'redirect': url_for('routes.home')})

            return jsonify({'message': 'Login failed. Check your email and password.'}), 401

        except Exception as e:
            return jsonify({'message': f'Error: {str(e)}'}), 500


@routes_blueprint.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.json['email']
            password = request.json['password']
            name = request.json['name']
            role = request.json['role']
            applied_job_role = request.json.get('applied_job_role')

            existing_user = User.query.filter_by(email=email).first()

            if existing_user:
                return jsonify({'message': 'Email already exists. Choose a different one.'}, 400)

            # Create a new user
            new_user = User(email=email, name=name, applied_job_role=applied_job_role, user_type=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            # Create a new candidate associated with the registered user
            new_candidate = Candidate(name=name, email=email)
            db.session.add(new_candidate)
            db.session.commit()

            return jsonify({'message': 'Registration successful! You can now log in.'})

        except Exception as e:
            return jsonify({'message': f'Registration failed. Error: {str(e)}'}, 500)

    # Return an error response if the request method is not POST
    return jsonify({'message': 'Invalid request method'}, 405)



@routes_blueprint.route('/hr')
def index():
    return redirect('/hr')


def send_emails(emails):
    responses = []

    for recipient_email in emails:
        if recipient_email:
            message = Message(
                subject='HR Round Results',
                body='Congratulations! You are Selected for the HR Round.',
                sender='dev@funnelhq.co',
                recipients=[recipient_email]
            )

            try:
                mail.send(message)
                responses.append("Email sent successfully to {}".format(recipient_email))
                print("Email sent successfully to", recipient_email)
            except Exception as e:
                responses.append("Error sending email to {}: {}".format(recipient_email, e))
                print("Error sending email to {}: {}".format(recipient_email, e))
        else:
            responses.append("Invalid email address for a candidate")

    return responses


# @routes_blueprint.route('/send_emails', methods=['POST'])
# @login_required
# def send_emails_route():
#     emails = request.form.getlist('emails')

#     if emails:
#         responses = send_emails(emails)
#         return render_template('results.html', Status='success', Data={'responses': responses})
#     else:
#         return render_template('results.html', Status='error', Data={'error_message': 'No emails provided'})


@routes_blueprint.route('/send_emails', methods=['POST'])
@login_required
def send_emails_route():
    print('hhh')
    try:
        data = request.get_json()
        emails = data.get('emails', [])

        if emails:
            responses = send_emails(emails)
            return jsonify({'Status': 'success', 'Data': {'responses': responses}})
        else:
            return jsonify({'Status': 'error', 'Data': {'error_message': 'No emails provided'}})

    except Exception as e:
        return jsonify({'Status': 'error', 'Data': {'error_message': str(e)}})


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

@login_required
@routes_blueprint.route('/submit_response', methods=['POST'])
def submit_response():
    data = request.json
    candidate_name = data.get('candidate_name')
    question_id = data.get('question_id')
    response = data.get('response')

    candidate = Candidate.query.filter_by(name=candidate_name).first()
    if not candidate:
        candidate = Candidate(name=candidate_name,email=current_user.email)
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

def get_email(candidate_id):
    try:
        candidate = Candidate.query.get(candidate_id)
        if candidate:
            user = User.query.filter_by(email=candidate.email).first()
            if user:
                return user.email
    except Exception as e:
        print(f"Error in get_email function: {str(e)}")

    return None

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
        model="ft:gpt-3.5-turbo-0613:funnelhq::8psZjis3",
        messages=data,
        temperature=1,
        max_tokens=2000
    )

    best_fit_candidates = model_response['choices'][0]['message']['content']
    return best_fit_candidates


@routes_blueprint.route('/get_best_fit_candidates/<job_role>', methods=['GET'])
def get_best_fit_candidates(job_role):
    try:
        best_fit_candidates_str = find_best_fit_candidates(job_role)
        best_fit_candidates_dict = json.loads(best_fit_candidates_str)

        refined_candidates = []

        if 'best_fit_candidates' in best_fit_candidates_dict:
            for candidate in best_fit_candidates_dict['best_fit_candidates']:
                candidate_id = candidate.get('candidate_id', None)
                fit_score = candidate.get('fit_score', None)
                email = get_email(candidate_id)

                refined_candidate = {
                    'candidate_id': candidate_id,
                    'email': email,
                    'fit_score': fit_score
                }
                refined_candidates.append(refined_candidate)

            refined_data = {'best_fit_candidates': refined_candidates}

            return jsonify({'Status': 'success', 'Data': refined_data})
            # return render_template('results.html', Status='success', Data=refined_data)
        else:
            data={'best_fit_candidates': []}
            return jsonify({'Status': 'error','Data':data})
            # return render_template('results.html', Status='error', Data=None)

    except json.JSONDecodeError as e:
        # Handle JSON decoding error
        data={'best_fit_candidates': []}
        error_message = f"Error decoding JSON: {str(e)}"
        return jsonify({'Status': 'error','Data':data})
        # return render_template('results.html', Status='error', Data={'error_message': error_message})

    except Exception as e:
        # Handle other unexpected errors
        data={'best_fit_candidates': []}
        error_message = f"An unexpected error occurred: {str(e)}"
        return jsonify({'Status': 'error','Data':data})
        # return render_template('results.html', Status='error', Data={'error_message': error_message})