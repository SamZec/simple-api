#!/bin/python3
"""Users view module"""
from api.v1.views import app_views
from flasgger.utils import swag_from
from models.auth import auth_role, Auth
from flask_jwt_extended import jwt_required
from models.users import User, Role, SetRole
from flask import jsonify, abort, request, session
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity


auth = Auth()

@app_views.route('/auth/register', methods=['POST'], strict_slashes=False)
@swag_from('documentation/users/auth_register.yml')
def register_user():
    """Create new user"""
    data = {}
    if request.is_json:
        data = request.get_json()
    first_name = data.get('first_name', request.form.get('first_name'))
    if not first_name:
        abort(400, 'first name missing')
    data['first_name'] = first_name
    last_name = data.get('last_name', request.form.get('last_name'))
    if not last_name:
        abort(400, 'lasst name missing')
    data['last_name'] = last_name
    email = data.get('email', request.form.get('email'))
    if not email:
        abort(400, 'email missing')
    data['email'] = email
    password = data.get('password', request.form.get('password'))
    if not password:
        abort(400, 'password missing')
    data['password'] = password
    try:
        user = auth.register_user(**data)
        return jsonify({
            'msg': f'user {user.email} created'}), 201
    except Exception as e:
        abort(500, str(e))


@app_views.route('auth/login', methods=['POST'], strict_slashes=False)
@swag_from('documentation/users/auth_login.yml')
def auth_login():
    """log authorized users in"""
    data = {}
    if request.is_json:
        data = request.get_json()
    email = data.get('email', request.form.get('email'))
    if not email:
        abort(400, 'email missing')
    password = data.get('password', request.form.get('password'))
    if not password:
        abort(400, 'password missing')
    try:
        auth_user = auth.valid_login(email, password)
        if auth_user:
            session_id = auth.create_session(email)
            user = auth.get_user_from_session_id(session_id)
            identity = {
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'session_id': user.session_id
                    }
            token = create_access_token(identity=identity)
            return jsonify({
                'msg': 'loggin successful',
                'access_token': token}), 200
    except Exception as e:
        abort(500, str(e))
    return abort(401, 'unauthorized user')


@app_views.route('/auth/otp-request', methods=['POST'], strict_slashes=False)
@swag_from('documentation/users/auth_otp_request.yml')
def otp_request():
    """OTP log in request"""
    data = {}
    if request.is_json:
        data = request.get_json()
    email = data.get('email', request.form.get('email'))
    if not email:
        abort(400, 'email missing')
    user = User.search({'email': email})
    if not user:
        abort(403, 'action forbidden')
    user = user[0]
    if auth.email_verification(email):
        try:
            OTP = auth.send_otp_code(email)
            session['OTP'] = OTP
            return jsonify({
                'msg': f'OTP sent to {email}, verify and log in'}), 200
        except Exception as e:
            abort(500, str(e))
    return jsonify({
        'msg': f'Invalid email {email}'}), 400


@app_views.route('/auth/otp-login', methods=['POST'], strict_slashes=False)
@swag_from('documentation/users/auth_otp_login.yml')
def otp_login():
    """logs user in with requested OTP"""
    data = {}
    if request.is_json:
        data = request.get_json()
    email = data.get('email', request.form.get('email'))
    if not email:
        abort(400, 'email missing')
    OTP = data.get('otp', request.form.get('otp'))
    if not OTP:
        abort(400, 'OTP missing')
    if session['OTP'] == int(OTP):
        try:
            session_id = auth.create_session(email)
            user = auth.get_user_from_session_id(session_id)
            identity = {
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'session_id': user.session_id
                    }
            token = create_access_token(identity=identity)
            session['OTP'] = None
            return jsonify({
                'msg': 'loggin successful',
                'access_token': token}), 200
        except Exception as e:
            abort(500, str(e))
    return abort(401, 'Invalid OTP')


@app_views.route('/auth/assign-role', methods=['POST'], strict_slashes=False)
@jwt_required()
@auth_role('Admin')
@swag_from('documentation/users/auth_assign_role.yml')
def assign_role():
    """assign user to a role"""
    data = {}
    if request.is_json:
        data = request.get_json()
    role = data.get('role', request.form.get('role'))
    if not role:
        abort(400, 'role missing')
    data['role'] = role
    user_id = data.get('user_id', request.form.get('user_id'))
    if not user_id:
        abort(400, 'user id missing')
    data['user_id'] = user_id
    user = User.get(id=user_id)
    if not user:
        abort(404, f'user {user_id} not found')
    get_role = Role.search({'name': role.capitalize()})
    if get_role:
        get_role = get_role[0]
        set_role = SetRole.search({'role_id': get_role.id})
        if set_role and set_role[0].user_id == user.id:
            abort(400, f'role {get_role.name} exists on {user_id}')
    else:
        try:
            get_role = Role(name=role.capitalize())
            get_role.save()
        except Exception as e:
            abort(500, str(e))
    try:
        set_role = SetRole(role_id=get_role.id, user_id=user_id)
        set_role.save()
    except Exception as e:
        abort(500, str(e))
    return jsonify({
        'msg': f'Role {get_role.name} assigned to {user_id}'}), 201


@app_views.route('/profile', strict_slashes=False)
@jwt_required()
@auth_role(['Admin', 'User'])
@swag_from('documentation/users/profile.yml')
def profile():
    """user profile"""
    session_id = get_jwt_identity().get('session_id')
    user = auth.get_user_from_session_id(session_id)
    if not user:
        abort(401, 'unauthorized user')
    user_json = user.to_json()
    return jsonify({
        'data': user_json,
        'msg': 'user profile'}), 200


@app_views.route('/profile', methods=['PUT'], strict_slashes=False)
@jwt_required()
@auth_role(['Admin', 'User'])
@swag_from('documentation/users/update_profile.yml')
def update_profile():
    """user profile"""
    session_id = get_jwt_identity().get('session_id')
    user = auth.get_user_from_session_id(session_id)
    if not user:
        abort(401, 'unauthorized user')
    if request.is_json:
        data = request.get_json()
    email = data.get('email', request.form.get('email'))
    if email:
        user.email = email
    first_name = data.get('first_name', request.form.get('first_name'))
    if first_name:
        user.first_name = first_name
    last_name = data.get('last_name', request.form.get('last_name'))
    if last_name:
        user.last_name = last_name
    try:
        user.update()
    except Exception as e:
        abort(500, str(e))
    user_json = user.to_json()
    del user_json['password']
    return jsonify({
        'data': user_json,
        'msg': 'user update successful'}), 200


@app_views.route('/users', strict_slashes=False)
@jwt_required()
@auth_role(['Admin'])
@swag_from('documentation/users/users.yml')
def get_users():
    """all users"""
    users = [i.to_json() for i in User.all()]
    if not users:
        abort(404, 'users not found')
    return jsonify({
        'data': users}), 200


@app_views.route('/users/<id>', methods=['DELETE'], strict_slashes=False)
@jwt_required()
@auth_role(['Admin'])
@swag_from('documentation/users/user.yml')
def delete_user(id):
    """remove user from data base"""
    user = User.get(id=id)
    if not user:
        abort(404, 'user not found')
    user.remove()
    return {}, 200
