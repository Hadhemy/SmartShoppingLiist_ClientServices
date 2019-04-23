from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, types
from datetime import datetime
from userservice import db
from werkzeug import generate_password_hash, check_password_hash
from flask import current_app
from flask_login import UserMixin



# Follow Model

class Follow(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_follower_id = db.Column (db.Integer, db.ForeignKey ('group.idGroup'), nullable=False)
    follower_id = db.Column(db.Integer, db.ForeignKey('registreduser.id'), nullable=False)
    followed_at = db.Column(db.DateTime, default=datetime.utcnow())

    # Init constructor
    def __init__(self, follower_id, followed_at,group_follower_id ):
        self.follower_id = follower_id
        self.followed_at = datetime.utcnow()
        self.group_follower_id = group_follower_id