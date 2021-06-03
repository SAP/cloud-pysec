# pylint: disable=missing-docstring,invalid-name,missing-docstring
from flask import Flask, request, jsonify
from sap.xssec.constants import GRANTTYPE_JWT_BEARER

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
    grant_type = request.form.get('grant_type')
    authorization = request.authorization
    if not authorization:
        return 'No authorization header', 401
    if authorization.username != 'clientid' or authorization.password != 'clientsecret':
        return 'Invalid authorization header', 401
    if grant_type != GRANTTYPE_JWT_BEARER:
        return 'Invalid grant type', 400
    return jsonify({'access_token': 'access_token'})


@app.route('/mtls/oauth/token', methods=['POST'])
def return_token_mtls():
    grant_type = request.form.get('grant_type')
    if grant_type != GRANTTYPE_JWT_BEARER:
        return 'Invalid grant type', 400
    # TODO: certificate validation
    return jsonify({'access_token': 'access_token'})
