"""
CRUD
"""
from functools import wraps
import datetime
import re
from flask import jsonify, abort, request, make_response, url_for
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash
import jwt
from app import app, models, db
import config_local

auth = HTTPBasicAuth()
app.config["SQLALCHEMY_POOL_RECYCLE"] = 30
app.config['JSON_AS_ASCII'] = False


def token_required(func_token):
    """Token validation function"""
    @wraps(func_token)
    def decorated(*args, **kwargs):
        token = None
        if not request.json or 'token' not in request.json:
            abort(400, 'Token is None')
        else:
            token = request.json.get('token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            jwt.decode(token, config_local.SECRET_KEY)
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403

        return func_token(*args, **kwargs)

    return decorated


@app.route('/api-token-auth/', methods=['POST'])
def auth_user():
    """User authorization by email and password"""
    if not request.json or 'email' not in request.json:
        abort(400, 'Authorization field email are not filled')
    if not request.json or 'password' not in request.json:
        abort(400, 'Authorization field password are not filled')
    our_user = db.session.query(models.User).filter_by(email=request.json['email']).first()
    if our_user is not None:
        if check_password_hash(our_user.hash_password, request.json['password']):
            token = jwt.encode(
                {'email': our_user.email,
                 'id': our_user.id,
                 'role': our_user.role,
                 'active': our_user.active,
                 'url': url_for('get_user', user_id=our_user.id, _external=True),
                 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)},
                config_local.SECRET_KEY)
            res = jsonify({'token': token.decode('UTF-8')}), 201
        else:
            res = jsonify({'error': 'Unauthorized access'})
    else:
        res = jsonify({'error': 'Unknown user'})
    return res


@app.route('/api-token-auth/', methods=['GET', 'PUT', 'DELETE'])
def auth_user_get():
    """Filter unused methods for authorization"""
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.route('/api/v1/users/<int:user_id>/', methods=['GET'])
@token_required
def get_user(user_id):
    """Get user fields by id"""
    user = models.User.query.get(user_id)
    if user is None:
        abort(404)
    return jsonify({'user': user_by_id(user_id)}), 201


@app.route('/api/v1/users/', methods=['GET'])
@token_required
def get_users():
    """Get all user fields"""
    users = models.User.query.all()
    lt_users = []
    for user in users:
        lt_users.append(user_by_id(user.id))
    return jsonify({'users': lt_users}), 201


def user_by_id(id_elem):
    """JSON answer user fields by id"""
    user = models.User.query.get(id_elem)
    new_user_json = {
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'active': user.active,
        'url': url_for('get_user', user_id=user.id, _external=True)
    }
    return new_user_json


@app.route('/api/v1/users/', methods=['POST'])
def create_user():
    """Create new user with required fields: password, email.
    And optional fields: role, active, first_name, last_name"""
    if not request.json or 'email' not in request.json or 'password' not in request.json:
        abort(400)
    correct_email = re.match(r'([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?', request.json['email'])
    if not correct_email:
        abort(400, 'Email incorrect')
    our_user = db.session.query(models.User).filter_by(email=request.json['email']).first()
    if our_user is not None:
        return jsonify({'error': 'User already created'})
    users = models.User.query.all()
    if users:
        id_user = users[-1].id + 1
    else:
        id_user = 1
    if 'first_name' in request.json and len(request.json['first_name']) > 30:
        request.json['first_name'] = request.json['first_name'][:30]
    if 'last_name' in request.json and len(request.json['last_name']) > 30:
        request.json['last_name'] = request.json['last_name'][:120]
    if 'role' in request.json and int(request.json['role']) != 1 or int(request.json['role']) != 0:
        request.json['role'] = 0
    if 'active' in request.json and \
            int(request.json['active']) != 1 or \
            int(request.json['active']) != 0:
        request.json['active'] = 1
    new_user = models.User(
        id=id_user,
        hash_password=generate_password_hash((request.json['password'])),
        email=request.json['email'],
        role=request.json['role'],
        active=request.json['active'],
        first_name=request.json.get('first_name', ''),
        last_name=request.json.get('last_name', ''),
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify(user_by_id(id_user)), 201


@app.route('/api/v1/users/<int:user_id>/', methods=['PUT'])
@token_required
def update_user(user_id):
    """Update user by id with optional fields:
    password, email, role, active, first_name, last_name"""
    user = models.User.query.get(user_id)
    if user is None:
        abort(404)
    if not request.json:
        abort(400)
    if 'password' in request.json:
        user.hash_password = generate_password_hash(request.json['password'])
    if 'email' in request.json:
        user.email = request.json['email']
    if 'role' in request.json:
        user.role = request.json['role']
    if 'active' in request.json:
        user.active = request.json['role']
    if 'first_name' in request.json:
        user.first_name = request.json['first_name']
    if 'last_name' in request.json:
        user.last_name = request.json['last_name']
    db.session.commit()
    return jsonify(user_by_id(user_id)), 201


@app.route('/api/v1/users/<int:user_id>/', methods=['DELETE'])
@token_required
def delete_user(user_id):
    """Delete user by id"""
    user = models.User.query.get(user_id)
    if user is None:
        abort(404)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'result': True})
