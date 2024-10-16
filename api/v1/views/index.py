#!/bin/python3
"""Application Index module"""
from flask import jsonify
from api.v1.views import app_views
from flasgger.utils import swag_from


@app_views.route('/public-data', strict_slashes=False)
@swag_from('documentation/index/index.yml')
def index():
    """check app status"""
    return jsonify({
        'project': 'Authorization and Authentication System',
        'assigner': 'Ideation Axis',
        'assignee': 'Affum Samuel'
        }), 200
