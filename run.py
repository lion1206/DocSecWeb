"""
Main entry point for the ЗЭДКД application
"""
from app import create_app
from app.models import db, User
from werkzeug.security import generate_password_hash

app = create_app()

def create_tables():
    """Create database tables and initialize with default admin user"""
    with app.app_context():
        db.create_all()
        
        # Check if admin user exists, if not create one
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin',
                first_name='System',
                last_name='Administrator'
            )
            admin.set_password('admin123')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: admin / admin123")

if __name__ == '__main__':
    create_tables()
    app.run(debug=True, host='0.0.0.0', port=5000)