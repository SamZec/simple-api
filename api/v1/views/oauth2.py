#!/bin/python3
"""Oauth2 login module"""
from api.v1 import limiter
from decouple import config
from api.v1.views import app_views
from flasgger.utils import swag_from
import requests, urllib3, facebook, json, os
from flask import redirect, request, abort, jsonify


APP_ID = config('APP_ID')
REDIRECT_URL = 'http://localhost:4321/response'
APP_SECRET = config('APP_SECRET')
ACCESS_TOKEN = config('FB_ACCESS_TOKEN')


@app_views.route('/oauth2', strict_slashes=False)
@limiter.limit('3/hour')
@swag_from('documentation/oauht2/oauth2.yml')
def oauth2():
    """Oauth2 third party login"""
    try:
        APP_ID = config('APP_ID')
        REDIRECT_URL = 'http://localhost:4321/response'
        FB_URL = 'https://www.facebook.com/v21.0/dialog/oauth?'
        CLIENT_ID_ARG = f'client_id={APP_ID}&'
        REDIRECT_URL_ARG = f'redirect_uri={REDIRECT_URL}&'
        return jsonify({
            'msg': 'use link to authorize log in',
            'link': FB_URL + CLIENT_ID_ARG + REDIRECT_URL_ARG}), 200
    except Exception as e:
        abort(500, str(e))

@app_views.route('/response', strict_slashes=False)
#@swag_from('documentation/oauht2/response.yml')
def response():
    """oauth2 login callback function"""
    code = request.args.get('code')
    FB_URL = 'https://graph.facebook.com/v21.0/oauth/access_token?'
    CLIENT_ID_ARG = f'client_id={APP_ID}&'
    REDIRECT_URL_ARG = f'redirect_uri={REDIRECT_URL}&'
    APP_SECRET_ARG = f'client_secret={APP_SECRET}&'
    CODE_ARG = f'code={code}'
    path = FB_URL + CLIENT_ID_ARG + REDIRECT_URL_ARG + APP_SECRET_ARG

    res = requests.get(path + CODE_ARG)
    if res.json().get('access_token'):
        FB_URL = 'https://graph.facebook.com/debug_token?'
        INPUT_TOKEN_ARG = f"input_token={res.json().get('access_token')}&"
        ACCESS_TOKEN_ARG = f"access_token={config('ACCESS_TOKEN')}"
        veryfy = requests.get(FB_URL + INPUT_TOKEN_ARG + ACCESS_TOKEN_ARG)
        return veryfy.json()
    return res.json()
