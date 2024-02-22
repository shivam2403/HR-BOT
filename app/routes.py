from flask import Flask,flash,Blueprint, jsonify, request, render_template,redirect,session,abort,url_for,send_file
# from models import db, Candidate, Question, HRInput, CandidateResponse // when working in app directory
from app.models import db, Candidate, Question, HRInput, CandidateResponse
import openai,json,re,os,pathlib,requests,google.auth.transport.requests
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from google.oauth2 import id_token
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_mail import *
from random import *
from pyotp import TOTP
import pyotp
import logging
import time
from werkzeug.utils import secure_filename
from flask import current_app

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
    # redirect_uri="http://127.0.0.1:8000/callback" // when working in app directory but now we need to change redirect_uri in our google app also so when working in app directory make redirect_uri as "http://127.0.0.1:8000/callback"
    redirect_uri="http://localhost:5000/callback"
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

            if len(password)<8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
                return render_template('invalid_password.html')

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

        
def login_is_required(endpoint_name):
    def decorator(function):
        def wrapper(*args, **kwargs):
            if "google_id" not in session:
                return render_template('LoginRequired.html')
            else:
                return function(*args, **kwargs)
        wrapper.__name__ = endpoint_name
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

        session["google_id"] = id_info.get("email")
        session["name"] = id_info.get("name")
        session["email"] = id_info.get("email")

        local_user = Candidate.query.filter_by(email=session["email"]).first()

        if not local_user:
            return 'User not found'

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
        email = session.get('google_id')
        user = Candidate.query.filter_by(email=email).first()
        questions = Question.query.filter_by(job_role=job_role).all()

        if questions:
            return render_template('interview.html', questions=questions, user=user)
        else:
            return render_template('interview.html', questions=None, message='No questions available for this job role',user=user)
    except Exception as e:
        logging.error(f"Error in 'interview' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    

@routes_blueprint.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def user_profile(user_id):
    try:
        if "google_id" not in session:
            return render_template('LoginRequired.html')

        email = session.get('google_id')
        user = Candidate.query.filter_by(email=email).first()

        if user.id != user_id:
            return render_template('not_found.html')

        if request.method == 'POST':
            # Handle form submissions to update user profile
            new_resume_path = request.form.get('resume_path')

            if 'resume' in request.files:
                resume_file = request.files['resume']

                if resume_file and allowed_file(resume_file.filename):
                    # Save the uploaded resume file to a specific folder
                    upload_folder = 'uploads'
                    os.makedirs(upload_folder, exist_ok=True)

                    resume_filename = secure_filename(resume_file.filename)
                    new_resume_path = os.path.join(upload_folder, resume_filename)
                    resume_file.save(new_resume_path)

            # Update the user's resume_path in the database if a new resume is uploaded
            if new_resume_path:
                user.resume_path = new_resume_path

            user.skillset = request.form.get('skillset')
            user.linkedin_url = request.form.get('linkedin_url')
            user.github_link = request.form.get('github_link')
            user.twitter_link = request.form.get('twitter_link')
            user.portfolio_link = request.form.get('portfolio_link')

            db.session.commit()

            # Retrieve the file input value from the session
            sessionStorage_key = f'resumeInputValue_{user.id}'
            resume_input_value = session.pop(sessionStorage_key, None)

            return render_template('profile.html', user=user, resume_input_value=resume_input_value)

        return render_template('profile.html', user=user)
    except Exception as e:
        logging.error(f"Error in 'profile' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

    


ALLOWED_EXTENSIONS = {'pdf'}
def allowed_file(filename):
    try:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    except Exception as e:
        logging.error(f"Error in 'allowed_file' function: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@routes_blueprint.route('/upload_resume/<int:user_id>', methods=['POST'])
def upload_resume(user_id):
    try:
        if "google_id" not in session:
            return render_template('LoginRequired.html')

        user = Candidate.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if 'resume' in request.files:
            resume_file = request.files['resume']

            if resume_file.filename == '':
                return jsonify({'error': 'No selected file'}), 400

            if resume_file and allowed_file(resume_file.filename):
                # Save the uploaded resume file to a specific folder (create the folder if not exists)
                upload_folder = 'uploads'
                os.makedirs(upload_folder, exist_ok=True)

                resume_filename = secure_filename(resume_file.filename)
                resume_path = os.path.join(upload_folder, resume_filename)
                resume_file.save(resume_path)

                # Update the user's resume_path in the database
                user.resume_path = resume_path
                db.session.commit()

                # Store the file input value in the session for persistence
                sessionStorage_key = f'resumeInputValue_{user.id}'
                session[sessionStorage_key] = request.form.get('resumeInput')

                # Use flash to display a message after redirection
                flash('Resume uploaded successfully!', 'success')

                return redirect(url_for('routes.user_profile', user_id=user.id))
            else:
                return jsonify({'error': 'Invalid file format. Please upload a PDF file'}), 400
        else:
            return jsonify({'error': 'No file part in the request'}), 400
    except Exception as e:
        logging.error(f"Error in 'upload_resume' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    


@routes_blueprint.route('/resumes/<filename>', methods=['GET'])
def get_resume(filename):
    try:
        # Use send_file to serve the resume file
        return send_file(filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Error in 'get_resume' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    

@routes_blueprint.route('/remove_resume/<int:user_id>', methods=['POST'])
def remove_resume(user_id):
    try:
        if "google_id" not in session:
            return render_template('LoginRequired.html')

        user = Candidate.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check if the user has a resume to remove
        if user.resume_path:
            # Remove the resume file from the server
            os.remove(user.resume_path)

            # Update the user's resume_path in the database
            user.resume_path = None
            db.session.commit()

            flash('Resume removed successfully!', 'success')
            return jsonify({'message': 'Resume removed successfully'}), 200
        else:
            return jsonify({'error': 'No resume to remove'}), 400
    except Exception as e:
        logging.error(f"Error in 'remove_resume' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500



# Add the following function to check if the file is a valid profile picture format
def allowed_profile_picture(filename):
    try:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}
    except Exception as e:
        logging.error(f"Error in 'allowed_profile_picture' function: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@routes_blueprint.route('/upload_profile_picture/<int:user_id>', methods=['POST'])
def upload_profile_picture(user_id):
    try:
        if "google_id" not in session:
            return render_template('LoginRequired.html')

        user = Candidate.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if 'profile_picture' in request.files:
            profile_picture_file = request.files['profile_picture']

            if profile_picture_file.filename == '':
                return jsonify({'error': 'No selected file'}), 400

            if profile_picture_file and allowed_profile_picture(profile_picture_file.filename):
                # Save the uploaded profile picture file to the assets folder within static
                upload_folder = os.path.join(current_app.static_folder, 'assets', 'profile_pics')
                os.makedirs(upload_folder, exist_ok=True)

                profile_picture_filename = secure_filename(profile_picture_file.filename)
                profile_picture_path = os.path.join(upload_folder, profile_picture_filename)
                profile_picture_path = profile_picture_path.replace('\\', '/')
                profile_picture_file.save(profile_picture_path)

                # Update the user's profile_picture in the database
                # Set the relative path instead of the absolute path
                relative_path = os.path.relpath(profile_picture_path, current_app.static_folder)
                user.profile_picture_filename = relative_path

                db.session.commit()

                flash('Profile picture uploaded successfully!', 'success')

                # Redirect to the user's profile page
                return redirect(url_for('routes.user_profile', user_id=user.id))
            else:
                return jsonify({'error': 'Invalid file format. Please upload a valid image file'}), 400
        else:
            return jsonify({'error': 'No file part in the request'}), 400
    except Exception as e:
        logging.error(f"Error in 'upload_profile_picture' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/remove_profile_image')
def remove_profile_image():
    try:
        email = session.get('google_id')
        user = Candidate.query.filter_by(email=email).first()
        user.profile_picture_filename = None
        db.session.commit()

        return render_template('profile.html',user=user)
    except Exception as e:
        logging.error(f"Error in 'remove_profile_image' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/forgot_password')
def forgot_password():
    try:
        return render_template('email.html')
    except Exception as e:
        logging.error(f"Error in 'forgot_password' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500        


@routes_blueprint.route('/getotp', methods=['POST'])
def get_otp():
    try:
        error_message=None
        email = request.form.get('email')
        user = Candidate.query.filter_by(email=email).first()

        if user is None:
            error_message="User not found! Please try again."
            return render_template('email.html',error_message=error_message)

        secret_key=generate_secret_key()
        otp, generated_time = generate_otp(secret_key)
        send_otp_email(email, otp)
        session["temp_user_email"] = email
        session["temp_user_otp"] = otp
        session["temp_generated_time"] = generated_time
        session["temp_secret_key"] = secret_key

        return render_template('verify_otp_for_forgot_password.html',)
    except Exception as e:
        logging.error(f"Error in 'get_otp' route: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@routes_blueprint.route('/verify_otp_for_updating_password', methods=['POST'])
def verify_otp_for_updating_password():
    try:
        user_otp = request.form.get('otp')
        stored_email = session.get("temp_user_email")
        stored_otp = session.get("temp_user_otp")
        secret_key=session.get('temp_secret_key')
        generated_time=session.get('temp_generated_time')
        
        
        if validate_totp(stored_otp, secret_key, generated_time) and int(stored_otp)==int(user_otp):
            # session.pop("temp_user_email", None)
            session.pop("temp_user_otp", None)
            return render_template('update_password.html')
        else:
            logging.error("OTP Verification Failed")
            return render_template('Error.html')
    except Exception as e:
        logging.error(f"Exception during OTP verification: {str(e)}")
        return render_template('Error.html')
    

@routes_blueprint.route('/update_password', methods=['GET', 'POST'])
def update_password():
    try:
        error_message = None

        if request.method == 'POST':
            password = request.form.get('password')
            re_password = request.form.get('re-password')

            # Check if passwords match
            if password == re_password:
                if len(password)<8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
                    return render_template('update_password.html', error_message="Please enter a valid password.")

                # Hash the password
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                # Update the user's password in the database
                email = session.get("temp_user_email")
                session.pop("temp_user_email", None)
                user = Candidate.query.filter_by(email=email).first()
                user.password = hashed_password
                db.session.commit()

                return redirect('/login')
            else:
                error_message = "Passwords do not match. Please try again."
                session['error_message_shown'] = True

        # Render the password update form with the error message
        return render_template('update_password.html', error_message=error_message)
    except Exception as e:
        logging.error(f"Exception in 'update_password' route: {str(e)}")
        return render_template('Error.html')