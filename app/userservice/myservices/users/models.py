from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, types
from datetime import datetime
from userservice import db
from werkzeug import generate_password_hash, check_password_hash
from flask import current_app
from flask_login import UserMixin
from userservice.myservices.groups.models import Group





# Registred User Class/Model

class Registreduser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    image_profile= db.Column(db.String(20), nullable=False, default='default.jpg')
    password= db.Column(db.String(60), nullable=False)
    account_created_at = db.Column(db.DateTime,default=datetime.utcnow)
    isLogged = db.Column(db.Boolean,unique=False, default=False)
    isCreated = db.Column(db.Boolean,unique=False, default=True)
    groups = db.relationship('Group', backref='author', lazy='dynamic')

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'registreduser_id': self.id}).decode('utf-8')


    # Init constructor
    def __init__(self, firstname, lastname, email, phone_number, password, account_created_at, isLogged, isCreated):
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.phone_number = phone_number
        self.password = password
        # check result from server with expected datasword
        self.account_created_at = datetime.utcnow()
        self.isLogged = False
        self.isCreated = True

