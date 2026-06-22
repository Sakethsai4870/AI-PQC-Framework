import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'pqc-framework-dev-key-2024')
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///pqc_framework.db')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = db_url if not db_url.startswith('postgresql') else 'sqlite:///pqc_framework.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 5000))
