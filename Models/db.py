from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
# from werkzeug.security import *
import secrets
import bcrypt
import pyotp

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    confirmation_code = db.Column(db.String(100), unique=True, nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    login_code = db.Column(db.String(100), nullable=True)
    new_email = db.Column(db.String(100), nullable=True)

    # relacja one to one
    security = db.relationship('Security', backref='user', uselist=False, cascade='all, delete-orphan')

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.set_password(password)
        self.confirmation_code = secrets.token_urlsafe(32)

    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password = bcrypt.hashpw(password.encode('utf-8'), salt)
        # self.password = generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)
        # return check_password_hash(self.password, password)


class Security(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    two_fa = db.Column(db.Boolean, default=False)
    two_fa_code = db.Column(db.String(32), unique=True, nullable=True)
    activity_log = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.Boolean, default=True)
    login_session_count = db.Column(db.Integer, default=0)

    def __init__(self, user_id, activity_log=False, two_fa=False, email_code=True, login_session_count=0):
        self.user_id = user_id
        self.activity_log = activity_log
        self.two_fa = two_fa
        self.two_fa_code = pyotp.TOTP(pyotp.random_base32()).secret
        self.email_code = email_code
        self.login_session_count = login_session_count
