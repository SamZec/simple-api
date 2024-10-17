#!/usr/bin/python3
""" Flask Application """
from decouple import config
from flask_cors import CORS
from flasgger import Swagger
from api.v1 import limiter
from api.v1.views import app_views
from models.token_blocklist import TokenBlocklist
from datetime import timedelta, datetime, timezone
from flask_jwt_extended import JWTManager, get_jwt_identity
from flask_jwt_extended import create_access_token, get_jwt
from flask import Flask, render_template, make_response, jsonify


app = Flask(__name__)
limiter.init_app(app)
token_expiry = config('SESSION_DURATION')
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.config['SECRET_KEY'] = config('SECRET_KEY')
app.config["JWT_SECRET_KEY"] = config('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=int(token_expiry))

jwt = JWTManager(app)
app.register_blueprint(app_views)
cors = CORS(app, resources={r"/api/v1/*": {"origins": "*"}})


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload['jti']
    token = TokenBlocklist.search({'jti': jti})
    return token is not None

    
# Using an `after_request` callback, we refresh any token that is within 30
# minutes of expiring. Change the timedeltas to match the needs of your application.
@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=1))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            response.headers['Authorization'] = access_token
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response

@app.errorhandler(400)
def bad_request(error):
    """400 error handler"""
    return jsonify({
        'error': 400,
        'msg': error.description}), 400


@app.errorhandler(401)
def forbidden(error):
    """ 401 Error handler"""
    return jsonify({
        'error': 401,
        'msg': error.description}), 401

@app.errorhandler(403)
def forbidden(error):
    """ 403 Error handler"""
    return jsonify({
        'error': 403,
        'msg': error.description}), 403

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return jsonify({
        'error': 404,
        'msg': error.description}), 404

@app.errorhandler(405)
def not_allowed(error):
    """405 error handler"""
    return jsonify({
        'error': 405,
        'msg': error.description}), 405

@app.errorhandler(429)
def not_allowed(error):
    """429 error handler"""
    return jsonify({
        'error': 429,
        'msg': error.description}), 429

@app.errorhandler(500)
def sever_error(error):
    """500 error handler"""
    return jsonify({
        'error': 500,
        'msg': error.description}), 500

app.config['SWAGGER'] = {
    'title': 'SIMPLE API - IDEATION',
    'uiversion': 3
}

Swagger(app)


if __name__ == "__main__":
    """ Main Function """
    API_HOST = config('DB_API_HOST', default=None)
    API_PORT = config('DB_API_PORT', default=None)
    if not API_HOST:
        host = '0.0.0.0'
    if not API_PORT:
        port = '5000'
    app.run(threaded=False, use_reloader=True)
