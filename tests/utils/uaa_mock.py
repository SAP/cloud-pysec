# pylint: disable=missing-docstring,invalid-name,missing-docstring
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.before_request
def only_accepts_json():
    if request.headers.get('Accept') != 'application/json':
        response = jsonify('{"error": "Accept header is not application/json"}')
        response.status_code = 400
        return response

@app.route('/')
def ping():
    return 'OK'


@app.route('/401/oauth/token', methods=['POST'])
def return_401():
    return '', 401


@app.route('/500/oauth/token', methods=['POST'])
def return_500():
    return '', 500


@app.route('/correct/oauth/token', methods=['POST'])
def return_token():
    grant_type = request.args.get('grant_type')
    authorization = request.headers.get('Authorization')
    if not authorization:
        return 'No authorization header', 401

    if grant_type == 'user_token':
        if authorization.startswith('Bearer'):
            return jsonify({'refresh_token': 'refresh_token'})
        return 'Invalid bearer', 401

    if grant_type == 'refresh_token':
        if authorization == 'Basic Y2xpZW50aWQ6Y2xpZW50c2VjcmV0': # base64(clientid:clientsecret)
            return jsonify({'access_token': 'access_token'})
        return 'Invalid basic auth', 401

    return 'Invalid grant_type', 400
