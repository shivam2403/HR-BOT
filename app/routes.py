from flask import Flask,Blueprint, jsonify, request, render_template,redirect,session,abort,url_for
from models import db, Candidate, Question, HRInput, CandidateResponse
import openai,json,re,os,pathlib,requests,google.auth.transport.requests
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from google.oauth2 import id_token
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_mail import *
from random import *
from pyotp import TOTP
import base64,pyotp
import secrets
import logging
import time

# Setup logging configuration
logging.basicConfig(filename='error.log', level=logging.ERROR)

load_dotenv()

app = Flask(__name__, template_folder='templates')
mail=Mail(app)
bcrypt = Bcrypt(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']='ss6928228@gmail.com'
app.config['MAIL_PASSWORD']='onbb hvfg dmeh ahyx'
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
app.config['MAIL_DEFAULT_SENDER'] = 'ss6928228@gmail.com'
mail.init_app(app)

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
client_secrets_file=os.path.join(pathlib.Path(__file__).parent, 'client_secret.json')

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:8000/callback"
    )

routes_blueprint = Blueprint('routes', __name__)
@routes_blueprint.route('/hr')
def index():
    try:
        return render_template('hr.html')
    except Exception as e:
        logging.error(f"Error in 'index' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/save_hr_input_and_generate_questions', methods=['POST'])
def save_hr_input_and_generate_questions():
    try:
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
    except Exception as e:
        logging.error(f"Error in 'save_hr_input_and_generate_questions' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500



def generate_hr_questions(role):
    try:
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
    except Exception as e:
        logging.error(f"Error in 'generate_hr_questions': {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


def extract_questions(generated_questions):
    try:
        return [q.strip() for q in re.split(r'\n\s*\d+\.\s*', generated_questions) if q.strip()]
    except Exception as e:
        logging.error(f"Error in 'extract_questions': {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/save_questions/<job_role>', methods=['POST'])
def save_questions(job_role):
    try:
        generated_questions = generate_hr_questions(job_role)

        for question_content in extract_questions(generated_questions):
            new_question = Question(content=question_content, job_role=job_role)
            db.session.add(new_question)
            db.session.commit()

        return jsonify({'message': f'Questions for {job_role} role saved successfully'})
    except Exception as e:
        logging.exception("An error occurred in 'save_questions' route: %s", str(e))
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/get_question/<job_role>', methods=['GET'])
def get_question(job_role):
    try:
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
    except Exception as e:
        logging.error(f"Error in 'get_question' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    
@routes_blueprint.route('/submit_response', methods=['POST'])
def submit_response():
    try:
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
    except Exception as e:
        logging.error(f"Error in 'submit_response' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


def find_best_fit_candidates(job_role):
    try:
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
    except Exception as e:
        logging.error(f"Error in 'find_best_fit_candidates': {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

   

@routes_blueprint.route('/get_best_fit_candidates/<job_role>', methods=['GET'])
def get_best_fit_candidates(job_role):
    try:
        
        best_fit_candidates = find_best_fit_candidates(job_role)

        
        return jsonify({'Status':'success','Data': best_fit_candidates})

    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        return jsonify({'error': error_message}), 500
  

def send_otp_email(to_email, otp):
    try:
        subject = "Login OTP for HR Bot"
        body = f"Your OTP for HR Bot login is: {otp}"
        sender = "ss6928228@gmail.com"
        msg = Message(subject, recipients=[to_email], body=body,sender=sender)
        mail.send(msg)
    except Exception as e:
        logging.error(f"Error in 'send_otp_email': {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

    
def generate_secret_key():
    try:
        return pyotp.random_base32()
    except Exception as e:
        logging.error(f"Error in 'generate_secret_key' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


def generate_otp(secret_key):
    try:
        totp = pyotp.TOTP(secret_key)
        otp = totp.now()
        return otp, time.time()
    except Exception as e:
        logging.error(f"Error in 'generate_otp': {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


def validate_totp(otp, secret_key, generated_time, validity_period=300):
    try:
        totp = pyotp.TOTP(secret_key)
        current_time = time.time()
        elapsed_time = current_time - generated_time
        if int(elapsed_time) <= int(validity_period):
            return True
        else:
            return False
    except Exception as e:
        logging.error(f"Error in 'validate_totp' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/verify', methods=['POST'])
def verify():
    try:
        user_otp = request.form.get('otp')
        stored_email = session.get("temp_user_email")
        stored_otp = session.get("temp_user_otp")
        secret_key=session.get('temp_secret_key')
        generated_time=session.get('temp_generated_time')
        
        
        if validate_totp(stored_otp, secret_key, generated_time) and int(stored_otp)==int(user_otp):
            session["google_id"] = stored_email
            session.pop("temp_user_email", None)
            session.pop("temp_user_otp", None)
            return redirect('/')
        else:
            logging.error("OTP Verification Failed")
            return render_template('Error.html')
    except Exception as e:
        logging.error(f"Exception during OTP verification: {str(e)}")
        return render_template('Error.html')


@routes_blueprint.route('/login', methods=['GET','POST'])
def login():
    try:
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = Candidate.query.filter_by(email=email).first()

            if user and bcrypt.check_password_hash(user.password, password):
                secret_key=generate_secret_key()
                otp, generated_time = generate_otp(secret_key)
                send_otp_email(user.email, otp)
                session["temp_user_email"] = user.email
                session["temp_user_otp"] = otp
                session["temp_generated_time"] = generated_time
                session["temp_secret_key"] = secret_key
                return render_template('verify.html')

            else:
                return render_template('Error.html')

        return render_template('login.html')
    except Exception as e:
        logging.error(f"Error in 'login' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/signup', methods=['GET','POST'])
def signup():
    try:
        if request.method == 'POST':
            username=request.form.get('username')
            email=request.form.get('email')
            password=request.form.get('password')
            phone=request.form.get('phone')

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            user=Candidate(username=username, phone=phone, email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            return redirect('/login')

        users=Candidate.query.all()
        return render_template('signup.html',users=users)
    except Exception as e:
        logging.error(f"Error in 'signup' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

# def login_is_required(function):
#     try:
#         def wrapper(*args, **kwargs):
#             if "google_id" not in session:
#                 return render_template('LoginRequired.html')
#             else:
#                 return function()
#         return wrapper
#     except Exception as e:
#         logging.error(f"Error in 'login_is_required' function: {str(e)}")
#         return jsonify({'error': 'An unexpected error occurred'}), 500
        
def login_is_required(endpoint_name):
    def decorator(function):
        def wrapper(*args, **kwargs):
            if "google_id" not in session:
                return render_template('LoginRequired.html')
            else:
                return function(*args, **kwargs)
        wrapper.__name__ = endpoint_name  # Set the endpoint name
        return wrapper
    return decorator



@routes_blueprint.route('/')
@login_is_required(endpoint_name='/')
def home():
    try:
        email = session.get('google_id')
        user = Candidate.query.filter_by(email=email).first()
        
        if user:
            return render_template('index.html', user=user)
        else:
            google_name = session.get('name')
            google_email = session.get('email')
            return render_template('index.html', google_name=google_name, google_email=google_email)
    except Exception as e:
        logging.error(f"Error in 'home' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/google_login')
def google_login():
    try:
        authorization_url, state = flow.authorization_url()
        session["state"]=state
        return redirect(authorization_url)
    except Exception as e:
        logging.error(f"Error in 'google_login' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@routes_blueprint.route('/callback')
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)

        if not session['state']==request.args['state']:
            abort(500)

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)
        clock_skew_in_seconds = int

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10
        )

        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")
        session["email"] = id_info.get("email") 
        return redirect("/")
    except Exception as e:
        logging.error(f"Error in 'callback' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/google_logout')
def google_logout():
    try:
        session.clear()
        return redirect('/login')
    except Exception as e:
        logging.error(f"Error in 'google_logout' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/result')
def result():
    try:
        email = session.get('google_id')
        user = Candidate.query.filter_by(email=email).first()
        
        if user:
            return render_template('result.html', user=user)
        else:
            google_name = session.get('name')
            google_email = session.get('email')
            return render_template('result.html', google_name=google_name, google_email=google_email)
    except Exception as e:
        logging.error(f"Error in 'result' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    

@routes_blueprint.route('/interview/<job_role>')
def interview(job_role):
    try:
        questions = Question.query.filter_by(job_role=job_role).all()

        if questions:
            return render_template('interview.html', questions=questions)
        else:
            return render_template('interview.html', questions=None, message='No questions available for this job role')
    except Exception as e:
        logging.error(f"Error in 'interview' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    


@routes_blueprint.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def user_profile(user_id):
    try:
        if "google_id" not in session:
            return render_template('LoginRequired.html')
        else:
            user = Candidate.query.get(user_id)

            if request.method == 'POST':
                # Handle form submissions to update user profile
                user.resume_path = request.form.get('resume_path')
                user.skillset = request.form.getlist('skillset')  # Use getlist for arrays
                user.linkedin_url = request.form.get('linkedin_url')
                user.github_link = request.form.get('github_link')
                user.other_links = request.form.get('other_links')

                db.session.commit()
                return redirect(url_for('routes.user_profile', user_id=user.id))

            return render_template('profile.html', user=user)
    except Exception as e:
        logging.error(f"Error in 'profile' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500