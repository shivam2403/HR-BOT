from flask import Flask
from app.models import db
from dotenv import load_dotenv
import os
import openai
from .routes import routes_blueprint

def create_app():
    app = Flask(__name__, template_folder='templates')
    load_dotenv() 
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    openai.api_key = os.environ['OPENAI_API_KEY']
    app.secret_key = os.environ.get('SECRET_KEY')
    app.register_blueprint(routes_blueprint)
    db.init_app(app)
    
 
    return app


