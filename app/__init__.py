from flask import Flask
from models import db
from dotenv import load_dotenv
import os,openai
from routes import routes_blueprint
from flask_mail import *
from random import *


def create_app():
    app = Flask(__name__, template_folder='templates')
    mail=Mail(app)

    load_dotenv()
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///hrbotDataB.db"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    openai.api_key = os.environ['OPENAI_API_KEY']
    app.secret_key = os.environ.get('SECRET_KEY')

    
    app.register_blueprint(routes_blueprint)
    db.init_app(app)
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"]="1"

    return app


if __name__ == '__main__':
    create_app().run(debug=True, port=8000)