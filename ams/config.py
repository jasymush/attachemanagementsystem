import os

class Config:
    # Secret key for Flask sessions and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key_for_dev'

    # Database configuration for PostgreSQL
    # Replace 'user', 'password', 'host', 'port', 'database' with your PostgreSQL credentials
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'postgresql://postgres:5555@localhost:5432/attache_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False # Disable tracking modifications for performance
