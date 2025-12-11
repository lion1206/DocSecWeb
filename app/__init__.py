"""
Main application factory for the secure document workflow system
"""
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from .models import db

login_manager = LoginManager()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zedkd.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    # Set login view
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Import and register blueprints
    from .auth import auth_bp
    from .main import main_bp
    from .documents import documents_bp
    from .admin import admin_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)
    
    # Register the Jinja2 global function for role checking
    @app.context_processor
    def inject_functions():
        return {
            'has_role': lambda user, role: user.role == role
        }
    
    return app

@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))