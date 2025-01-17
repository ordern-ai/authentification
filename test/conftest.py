import pytest
import os
from datetime import datetime



def pytest_configure(config):
    """Configure test environment"""
    os.environ['TESTING'] = 'True'
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    os.environ['SECRET_KEY'] = 'test-secret-key'
    os.environ['MAIL_SERVER'] = 'smtp.test.com'
    os.environ['MAIL_USERNAME'] = 'test@test.com'
    os.environ['MAIL_PASSWORD'] = 'test-password'
    os.environ['MAIL_DEFAULT_SENDER'] = 'test@test.com'
    os.environ['TWILIO_ACCOUNT_SID'] = 'test-sid'
    os.environ['TWILIO_AUTH_TOKEN'] = 'test-token'
    os.environ['TWILIO_PHONE_NUMBER'] = '+1234567890'