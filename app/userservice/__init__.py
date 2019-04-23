from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import os

# Locate the DB file

basedir = os.path.abspath(os.path.dirname(__file__))


# Init app

app = Flask(__name__)

# Init db

db = SQLAlchemy(app)

# Bcrypt
bcrypt = Bcrypt(app)

# Init mail
mail = Mail(app)


# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
RESERVE_CONTEXT_ON_EXCEPTION = False
app.config['SECRET_KEY'] = "thisismysecretkey!"
app.config['FLASKY_GROUPS_PER_PAGE'] =  3
app.config['FLASKY_FOLLOWERS_PER_PAGE'] = 3
MAIL_SERVER = 'smtp.googlemail.com'
login_manager = LoginManager(app)
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = os.environ.get('EMAIL_USER')
MAIL_PASSWORD = os.environ.get('EMAIL_PASS')
# Init marshmallow
ma = Marshmallow(app)
from userservice.myservices.users.routes import users
from userservice.myservices.groups.routes import groups
from userservice.myservices.followers.routes import followers


app.register_blueprint(users)
app.register_blueprint(groups)
app.register_blueprint(followers)


   #app.register_blueprint(userservice.api.routes.mod, url_prefix='/api')

