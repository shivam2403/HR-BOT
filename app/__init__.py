from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from .routes import routes_blueprint
from .models import db, User
import os
from .extensions import db, login_manager, mail

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__, template_folder='templates')

    load_dotenv()
    current_folder = os.path.abspath(os.path.dirname(__file__))
    database_path = os.path.join(current_folder, '..', 'instance', 'que3.db')

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + database_path
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = os.environ.get('SECRET_KEY')


    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

    # Register blueprints
    app.register_blueprint(routes_blueprint)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)  # Initialize login_manager here
    mail.init_app(app)


    with app.app_context():
        db.create_all()

    login_manager.login_view = 'routes.login'

    return app

# if __name__ == '__main__':
#     app_instance = create_app()

#     app_instance.run(host='0.0.0.0', port=5000, debug=True)
