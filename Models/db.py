from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import *

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    confirmation_code = db.Column(db.String(100), unique=True, nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    login_code = db.Column(db.String(100), nullable=True)

    #relacja one to one
    security = db.relationship('Security', backref='user', uselist=False, cascade='all, delete-orphan')

    # dodaj baze dla activity log

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.set_password(password)
        self.confirmation_code = secrets.token_urlsafe(32)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Security(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    two_fa = db.Column(db.Boolean, default=False)
    activity_log = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.Boolean, default=True)

    def __init__(self, user_id, activity_log=False, two_fa=False, email_code=True):
        self.user_id = user_id
        self.activity_log = activity_log
        self.two_fa = two_fa
        self.email_code = email_code
