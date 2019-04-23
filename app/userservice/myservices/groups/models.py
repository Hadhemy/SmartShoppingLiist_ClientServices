from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, types
from datetime import datetime
from userservice import db
from werkzeug import generate_password_hash, check_password_hash
from flask import current_app
from flask_login import UserMixin
from userservice.myservices.followers.models import Follow
# Group Model

class Group (UserMixin,db.Model):
    idGroup = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), unique=True, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('registreduser.id'), nullable=False)
    followers = db.relationship('Follow',backref='follower', lazy='dynamic')

    # Init constructor
    def __init__(self, title, date_created, created_by):
        """

        :rtype: object
        """
        self.title = title
        self.date_created = datetime.utcnow()
        self.created_by = created_by

