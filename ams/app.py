from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from models import db, User, Report
from routes import auth_bp, main_bp # Import blueprints
from config import Config # Import Config class

def create_app():
    """
    Factory function to create and configure the Flask application.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize SQLAlchemy with the Flask app
    db.init_app(app)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login' # Specify the login view

    @login_manager.user_loader
    def load_user(user_id):
        """
        Callback function for Flask-Login to load a user from the database.
        """
        # Using .get() on the session directly is the recommended SQLAlchemy 2.0 way
        # For SQLAlchemy 1.x, User.query.get() is still valid but will show a warning.
        return db.session.get(User, int(user_id))


    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()

    @app.route('/')
    def index():
        """
        Redirects the root URL to the login page.
        """
        return redirect(url_for('auth.login'))

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True) # Run in debug mode for development
