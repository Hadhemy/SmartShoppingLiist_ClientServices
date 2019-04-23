from flask import request, jsonify, Blueprint, current_app, url_for, make_response
from flask_marshmallow import Marshmallow
from userservice.myservices.users.models  import Registreduser
from userservice.myservices.groups.models import Group
from userservice import db, bcrypt, login_manager, app
from flask_login import login_user, current_user, logout_user, login_required
from userservice.myservices.users.utils import save_picture
from userservice.myservices.decorators import require_appkey, token_required
import jwt
from datetime import datetime

users = Blueprint('users', __name__)
# Init marshmallow
ma = Marshmallow(users)
# User Schema
class UserSchema(ma.Schema):
  class Meta:
    fields = ('id', 'firstname', 'lastname', 'email', 'phone_number', 'password', 'account_created_at', 'isLogged', 'isCreated')

# Init schema
user_schema = UserSchema(strict=True)
users_schema = UserSchema(many=True, strict=True)


# Create account
@users.route('/user/signup', methods=['POST'])
@require_appkey
def create_account():
    email = request.json['email']
    # Fetch user
    user = Registreduser.query.filter_by(email=email).first()
    if user is None:
        firstname = request.json['firstname']
        lastname = request.json['lastname']
        email= request.json['email']
        phone_number = request.json['phone_number']
        password = request.json['password']
        password = bcrypt.generate_password_hash (request.json['password']).decode ('utf-8')
        isLogged = True
        isCreated = True
        new_user = Registreduser(firstname, lastname, email, phone_number, password, datetime.utcnow(), isLogged, isCreated)
        db.session.add(new_user)
        db.session.commit()
        #return user_schema.jsonify(new_user)
        return jsonify ({
            'isCreated': isCreated,
            'msg': 'New account successfully created !'
        })
    else:
         isCreated = True
         return jsonify({
        'isCreated': isCreated,
        'msg': 'Email address is already registred !'
        })

# Get All Users
@users.route('/user', methods=['GET'])
@require_appkey
@token_required
def get_users(current_user):
    if not current_user:
        return jsonify ({ 'message': 'Cannot perform that function, token is missing!' })
    all_users =Registreduser.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result.data)

# Get Single User
@users.route('/user/<int:id>/<string:email>', methods=['GET'])
@require_appkey
@token_required
def get_user(current_user,id,email):
    if not current_user:
        return jsonify ({ 'message': 'Cannot perform that function, token is missing!' })
    # Fetch user
    user = Registreduser.query.filter_by (email=email,id=id).first ()
    if not user:
      return jsonify({ 'msg': 'No user found!'
                       })
    return user_schema.jsonify(user)

# Get Single User mail
@users.route('/user/<int:id>', methods=['GET'])
@require_appkey
@token_required
def get_user_mail(current_user,id):
    if not current_user:
        return jsonify ({ 'message': 'Cannot perform that function, token is missing!' })
    # Fetch user
    user = Registreduser.query.filter_by (id=id).first ()
    if not user:
      return jsonify({ 'msg': 'No user found!'
                       })
    return jsonify({'email':user.email})

# Update user info
@users.route('/user/update', methods=['PUT'])
@require_appkey
@token_required
def update_user(current_user):
    if not current_user:
        return jsonify ({ 'message': 'Cannot perform that function, token is missing!' })
    email = request.json['email']
    # Fetch user
    user = Registreduser.query.filter_by (email=email).first ()
    if not user:
        return jsonify ({ 'msg': 'No user found!',
                          'isUpdated': False
                          })
    # update fields
    firstname = request.json['firstname']
    lastname = request.json['lastname']
    phone_number = request.json['phone_number']
    password = request.json['password']
    password = bcrypt.generate_password_hash (request.json['password']).decode ('utf-8')

    user.firstname = firstname
    user.lastname = lastname
    user.phone_number = phone_number
    user.password = password
    db.session.commit()

    return jsonify ({ 'msg': 'User successfully updated!',
                      'isUpdated': True,
                      'firstname': user.firstname,
                      'lastname' : user.lastname,
                      'phone_number': user.phone_number,
                      'password': user.password })


# Get user created groups
@users.route('/user/groups', methods=['GET'])
@require_appkey
@token_required
def get_user_created_groups(current_user):
    if not current_user:
        return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
    email = current_user.email
    # Fetch user
    user = Registreduser.query.filter_by (email=email).first ()
    if user is None:
        return jsonify({'msg': 'User is not registred'})
    page = request.args.get('page', 1, type=int)
    pagination = user.groups.order_by(Group.date_created.desc()).paginate(
        page, per_page=current_app.config['FLASKY_GROUPS_PER_PAGE'],
        error_out=False)
    groups = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('users.get_user_groups', id=id, page=page-1)
    next = None
    if pagination.has_next:
        next = url_for('users.get_user_groups', id=id, page=page+1)
    return jsonify({
        'groups names': [group.title for group in groups],
        'prev': prev,
        'next': next,
        'count': pagination.total})

# Log In
@users.route("/user/login", methods=['GET', 'POST'])
@require_appkey
def login():
    auth = request.authorization
    email = request.json['email']
    pwd = request.json['password']
    user = Registreduser.query.filter_by (email=email).first()

    if not user:

        return jsonify({ 'isLogged': False,
                         'msg': "User not registred !"})

    import datetime

    if bcrypt.check_password_hash(user.password, pwd):
        token = jwt.encode (
            { 'id': user.id, 'exp': datetime.datetime.utcnow () + datetime.timedelta (seconds=1800) },
            current_app.config['SECRET_KEY'])
        user.isLogged =True

        return jsonify ({ 'token': token.decode ('UTF-8'),
                          'isLogged': user.isLogged,
                          'firstname': user.firstname,
                          'lastname': user.lastname,
                          'email': user.email,
                          'phone_number': user.phone_number,
                          'msg': 'User successfully logged in !'
                          })

    user.isLogged = False
    return jsonify ({
        'isLogged': user.isLogged,
        'msg': 'Password incorrect !'
    })


# Logout
@users.route("/user/logout", methods=['GET', 'POST'])
@require_appkey
@token_required
def logout(current_user):
    import datetime
    if not current_user:
        return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
    user = Registreduser.query.filter_by (email=current_user.email).first ()
    if user is None:
        user.isLogged = True
        return jsonify ({
        'isLogged': user.isLogged,
        'msg': 'Failed to log out !'
    })
    else:
        user.isLogged = False
        db.session.commit()
        current_user = None
        logout_user()
        token = request.headers['x-access-token']
        yesterday = datetime.datetime.now() + datetime.timedelta(days=-1)
        token = None
        return jsonify ({
                'isLogged': user.isLogged,
                'msg': 'User successfully logged out !'
            })

# Delete user
@users.route('/user/delete/<int:id>/<string:email>', methods=['DELETE'])
@require_appkey
@token_required
def delete_user(current_user, id, email):
  if not current_user:
    return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
  # fetch user
  user = Registreduser.query.filter_by (id=id, email=email).first ()

  if not user:
    return jsonify ({ 'msg': 'No user found !' })

  db.session.delete (user)
  db.session.commit ()

  return jsonify ({ 'msg': 'User has been deleted !' })