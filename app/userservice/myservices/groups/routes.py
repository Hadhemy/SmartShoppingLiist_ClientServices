from flask import request, jsonify, Blueprint, current_app, url_for, make_response
from flask_marshmallow import Marshmallow
from userservice.myservices.groups.models import Group
from userservice.myservices.users.models import Registreduser
from userservice.myservices.followers.models import Follow
from userservice import db
from flask_login import login_user, current_user, logout_user, login_required
from userservice.myservices.decorators import require_appkey, token_required
import json
from datetime import datetime



# Init bluebripnt
groups = Blueprint('groups', __name__)

# Init marshmallow
ma = Marshmallow(groups)

# Group Schema
class GroupSchema(ma.Schema):
  class Meta:
    fields = ('idGroup', 'title', 'date_created', 'created_by')

# Init schema
group_schema = GroupSchema(strict=True)
groups_schema = GroupSchema(many=True, strict=True)


#Create a Group
@groups.route('/group', methods=['POST'])
@require_appkey
@token_required
def add_group(current_user):
  if not current_user:
    return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
  title = request.json['title']
  email = request.json['email']
  user = Registreduser.query.filter_by(email=email).first()
  # Fetch group
  group = Group.query.filter_by (title=title).first ()
  if not user:
    return jsonify({'msg' : 'User not found !'})
  if group:
    return jsonify({'msg': 'Group title is already taken !',
                    'isCreated': False})
  else:
    created_by =json.dumps(current_user.id)
    new_group = Group(title, datetime.utcnow(), created_by)
    db.session.add(new_group)
    db.session.commit()
    return jsonify ({ 'title' : title,
                    'created_by': user.email,
                    'msg' : 'New group successfully created !',
                     'isCreated': True})



# Get All Groups
@groups.route('/group', methods=['GET'])
@require_appkey
@token_required
def get_groups(current_user):
  if not current_user:
    return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
  created_by=json.dumps(current_user.id)
  all_groups =Group.query.filter_by(created_by=created_by).all()
  current_user.groups = all_groups
  if not all_groups:
    return jsonify({'msg': 'No group found !'})
  result = groups_schema.dump (all_groups)
  return jsonify(result.data)

# Get Single Group
@groups.route('/group/findone', methods=['GET'])
@require_appkey
@token_required
def get_group(current_user):
  if not current_user:
    return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
  created_by = json.dumps (current_user.id)
  title = request.json['title']
  group = Group.query.filter_by (title=title, created_by=current_user.id).first ()
  if not group:
    return jsonify({'msg': 'No group found with that title'})
  return group_schema.jsonify(group)

# Update group info
@groups.route('/group/update/<int:idGroup>', methods=['PUT'])
@require_appkey
@token_required
def update_group(current_user, idGroup):
  if not current_user:
    return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
  # Fetch group
  created_by = json.dumps (current_user.id)
  group = Group.query.filter_by (idGroup=idGroup, created_by=current_user.id).first ()
  if not group:
    return jsonify({'msg': 'No group found !',
                    'isUpdated':False})
  title = request.json['title']
  group.title = title
  db.session.commit()

  return jsonify ({ 'msg': 'Group successfully updated!',
                    'isUpdated': True,
                    'title':group.title,
                   })

# Delete Group
@groups.route('/group/delete', methods=['DELETE'])
@require_appkey
@token_required
def delete_group(current_user):
  if not current_user:
    return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
  title = request.json['title']
  group = Group.query.filter_by (title=title, created_by=current_user.id).first ()

  if not group:
    return jsonify ({ 'msg': 'No group found!' })

  db.session.delete (group)
  db.session.commit ()

  return jsonify ({ 'msg': 'Group successfully deleted!' })

# Get the followers of a  group
@groups.route('/group/followers', methods=['POST'])
@require_appkey
@token_required
def get_group_followers(current_user):
  if not current_user:
    return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })
  title = request.json['title']
  # fetch group
  group = Group.query.filter_by (title=title, created_by=current_user.id).first ()
  if not group:
    return jsonify ({ 'msg': 'No group found !' })
  page = request.args.get ('page', 1, type=int)
  pagination = group.followers.order_by (Follow.followed_at.desc ()).paginate (
    page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
    error_out=False)
  users = pagination.items
  mail = []
  tel = []
  name = []
  last = []
  for user in users:
    id =   user.follower_id
    follower = Registreduser.query.filter_by (id=id).first ()
    mail.append(follower.email)
    tel.append(follower.phone_number)
    name.append(follower.firstname + ' ' + follower.lastname)


  prev = None
  if pagination.has_prev:
    prev = url_for ('groups..get_groups', id=id, page=page - 1)
  next = None
  if pagination.has_next:
    next = url_for ('groups.get_groups', id=id, page=page + 1)
  return jsonify ({
    'group name': group.title,
    'follower id': [id],
    'follower email':[mail],
    'follower phone' : [tel],
    'follower name': [name],
    'prev': prev,
    'next': next,
    'count': pagination.total })

