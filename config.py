import os

class Config:
    # Secret key for Flask sessions and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key_for_dev'

    # Database configuration for PostgreSQL
    # Replace 'postgres', '5555', 'localhost:5432', 'attaches_db' with your PostgreSQL credentials
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'postgresql://postgres:5555@localhost:5432/attaches_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False # Disable tracking modifications for performance

    # Flask-Mail Configuration
    # ---------------------------------------------------------------------
    # 1. MAIL_SERVER: Enter your email provider's SMTP server address.
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'

    # 2. MAIL_PORT: Enter the port number for your SMTP server.
    #    - Common for TLS: 587
    #    - Common for SSL: 465
    #    Setting to 587 as it's common for TLS with Gmail
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587) 

    # 3. MAIL_USE_TLS / MAIL_USE_SSL: Set one to True, and the other to False.
    #    For port 587, TLS is typically used. For port 465, SSL is used.
    #    We'll explicitly set them based on the common Gmail setup (TLS on 587).
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true' # Default to True for TLS
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true' # Default to False for SSL
    
    # IMPORTANT: Ensure only one of MAIL_USE_TLS or MAIL_USE_SSL is True based on your port.
    # If using port 587, MAIL_USE_TLS should be True and MAIL_USE_SSL False.
    # If using port 465, MAIL_USE_SSL should be True and MAIL_USE_TLS False.


    # 4. MAIL_USERNAME: Enter the full email address you will use to send emails.
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'moeamsystem@gmail.com'

    # 5. MAIL_PASSWORD: Enter the password for the MAIL_USERNAME email account.
    #    - IMPORTANT for Gmail: If you have 2-Factor Authentication (2FA) enabled,
    #      you MUST generate an "App Password" from your Google Account security settings
    #      and use that here, NOT your regular Gmail password.
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'qmnd amzd chzp fjxc'

    # 6. MAIL_DEFAULT_SENDER: This is the email address that will appear as the "From" address.
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'moeamsystem@gmail.com'
    # ---------------------------------------------------------------------
