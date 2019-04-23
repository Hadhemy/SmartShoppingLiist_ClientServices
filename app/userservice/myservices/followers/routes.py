from flask import request, jsonify, Blueprint
from flask_marshmallow import Marshmallow
from userservice.myservices.users.models import Registreduser
from userservice.myservices.groups.models import Group
from userservice.myservices.followers.models import Follow
from userservice import db
from userservice.myservices.decorators import token_required, require_appkey
from flask_login import login_user, current_user, logout_user, login_required
from datetime import datetime

# Init bluebripnt
followers= Blueprint('followers', __name__)

# Init marshmallow
ma = Marshmallow(followers)

# Follow Schema
class FollowSchema(ma.Schema):
  class Meta:
    fields = ('id','follower_id', 'followed_at', 'group_follower_id' )

# Init schema
follow_schema = FollowSchema(strict=True)
followers_schema = FollowSchema(many=True, strict=True)


# Join a Group
@followers.route('/follow', methods=['POST'])
@require_appkey
@token_required
def join_group(current_user):
    if not current_user:
        return jsonify ({ 'msg': 'Cannot perform that function, token is missing!' })

    title = request.json['title']
    email = request.json['email']

    # fetch group
    group = Group.query.filter_by (title=title, created_by=current_user.id).first ()
    # fetch user by email
    user = Registreduser.query.filter_by (email=email).first ()
    #ing  = Follow.query.filter_by (group_follower_id = group.idGroup, follower_id=user.id).first()
    if not user:
        return jsonify ({ 'msg': 'User not registred !',
                          'isAdded': False })
    if not group:
        return jsonify ({ 'msg': 'No group found !' ,
                          'isAdded': False})

    if not Follow.query.filter_by (group_follower_id = group.idGroup, follower_id=user.id).first() :
        new_follower = Follow (user.id, datetime.utcnow (), group.idGroup)
        db.session.add (new_follower)
        db.session.commit ()
        return jsonify ({ 'groupName': group.title,
                          'follower email': user.email,
                          'msg': 'New user successfully added in the group !',
                          'isAdded': True })

    return jsonify ({ 'msg': 'User already in the group !',
                          'isAdded': True })



