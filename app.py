from flask import Flask, render_template, redirect, url_for, flash, request, current_app
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_migrate import Migrate
from flask_mail import Mail
from models import db, User, Report
from routes import auth_bp, main_bp
from config import Config
import logging
from logging.handlers import RotatingFileHandler
import os # NEW: Import os module

# Global mail object (will be initialized in create_app)
mail = Mail()

def create_app():
    """
    Factory function to create and configure the Flask application.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize SQLAlchemy with the Flask app
    db.init_app(app)

    # Initialize Flask-Migrate
    migrate = Migrate(app, db)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        """
        Callback function for Flask-Login to load a user from the database.
        """
        return db.session.get(User, int(user_id))

    # Initialize Flask-Mail with the app
    mail.init_app(app)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Register custom error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback() # Ensure database session is rolled back on 500 errors
        return render_template('500.html'), 500

    # Configure logging
    if not app.debug and not app.testing:
        # File handler for general logs
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/ams.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        # Set app logger level
        app.logger.setLevel(logging.INFO)
        app.logger.info('Attaches Management System startup')


    @app.route('/')
    def index():
        """
        Redirects the root URL to the login page.
        """
        return redirect(url_for('auth.login'))

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0')
