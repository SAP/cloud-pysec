# pylint: disable=too-many-public-methods
""" Security Context class """
import functools
import re
import tempfile
from os import environ, unlink
import json
from datetime import datetime
import logging
from typing import Any, Dict

import httpx
import deprecation

from sap.xssec import constants
from sap.xssec.jwt_validation_facade import JwtValidationFacade, DecodeError
from sap.xssec.key_cache import KeyCache
from sap.xssec.jwt_audience_validator import JwtAudienceValidator

_client_secret_props = ('clientid', 'clientsecret', 'url')  # props for client secret authentication
_client_certificate_props = ("clientid", "certificate", "certurl")  # props for client certificate authentication


def _check_if_valid(item, name):
    if item is None:
        raise ValueError('"{0}" should not be None'.format(name))
    if isinstance(item, str) and len(item) < 1:
        raise ValueError('"{0}" should not be an empty string'.format(name))


def _check_config(config):
    _check_if_valid(config, 'config')
    if not _has_client_secret_props(config) and not _has_client_certificate_props(config):
        raise ValueError('Either {} or {} should be provided'.
                         format(','.join(_client_secret_props), ','.join(_client_certificate_props)))


def _has_client_secret_props(config):
    return all(map(functools.partial(_check_prop, config), _client_secret_props))


def _has_client_certificate_props(config):
    return all(map(functools.partial(_check_prop, config), _client_certificate_props))


def _check_prop(config: Dict[str, Any], prop: str) -> bool:
    item = None
    if prop in config:
        item = config[prop]
    try:
        _check_if_valid(item, 'config.{0}'.format(prop))
        return True
    except ValueError:
        return False


def _create_cert_and_key_files(cert_content, key_content):
    cert_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    cert_file.write(cert_content)
    cert_file.close()
    key_file = None
    if key_content is not None:
        key_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        key_file.write(key_content)
        key_file.close()
    return cert_file.name, key_file.name if key_file else None


def _delete_cert_and_key_files(cert_file_name, key_file_name):
    if cert_file_name:
        unlink(cert_file_name)
    if key_file_name:
        unlink(key_file_name)


class SecurityContextXSUAA(object):
    """ SecurityContext class """

    verificationKeyCache = KeyCache()

    def __init__(self, token, config):
        _check_if_valid(token, 'token')
        self._token = token
        _check_config(config)
        self._config = config
        self._jwt_validator = JwtValidationFacade()
        self._logger = logging.getLogger(__name__)
        self._properties = {}
        self._init_properties()

    def _init_properties(self):
        self._init_xsappname()
        self._set_properties_defaults()
        self._set_token_properties()
        self._offline_validation()
        self._audience_validation()

    def _init_xsappname(self):
        if 'xsappname' not in self._config:
            if 'XSAPPNAME' not in environ:
                raise ValueError('Invalid config: Missing xsappname.'
                                 ' The application name needs to be defined in xs-security.json.')
            else:
                self._logger.warning('XSAPPNAME defined in manifest.yml (legacy).'
                                     ' You should switch to defining xsappname'
                                     ' in xs-security.json.')
                self._properties['xsappname'] = environ['XSAPPNAME']
        else:
            self._properties['xsappname'] = self._config['xsappname']
            if 'XSAPPNAME' in environ:
                if self._config['xsappname'] == environ['XSAPPNAME']:
                    self._logger.warning('The application name is defined both in the manifest.yml'
                                         ' (legacy) as well as in xs-security.json.'
                                         ' Remove it in manifest.yml.')
                else:
                    raise ValueError('Invalid config: Ambiguous xsappname.'
                                     ' The application name is defined with different values in'
                                     ' the manifest.yml (legacy) as well as in xs-security.json.'
                                     ' Remove it in manifest.yml.')

    def _get_jku(self):
        uaa_domain: str = self._config.get('uaadomain') or self._config.get('url')
        if not uaa_domain:
            raise RuntimeError("Service is not properly configured in 'VCAP_SERVICES'")
        uaa_domain = re.sub(r'^https://', '', uaa_domain)
        payload = self._jwt_validator.decode(self._token, verify=False)
        zid = payload.get("zid")
        return f"https://{uaa_domain}/token_keys?zid={zid}" if zid else f"https://{uaa_domain}/token_keys"

    def _set_token_properties(self):

        def set_property(json_key):
            prop = decoded.get(json_key, None)
            self._properties[json_key] = prop

        try:
            decoded = self._jwt_validator.get_unverified_header(self._token)
        except DecodeError:
            raise ValueError("Failed to decode provided token")

        set_property("jku")
        set_property("kid")

    def _set_properties_defaults(self):
        self._properties['is_foreign_mode'] = False
        self._properties['user_info'] = {
            'logon_name': None,
            'given_name': None,
            'family_name': None,
            'email': None
        }
        self._properties['scopes'] = []
        self._properties['saml_token'] = None
        self._properties['subdomain'] = None
        self._properties['clientid'] = None
        self._properties['zone_id'] = None
        self._properties['subaccount_id'] = None
        self._properties['user_attributes'] = {}
        self._properties['additional_auth_attributes'] = {}
        self._properties['service_instance_id'] = None
        self._properties['grant_type'] = None
        self._properties['origin'] = None
        self._properties['expiration_date'] = None
        self._properties['jku'] = None
        self._properties['kid'] = None
        self._properties['uaadomain'] = None
        # Audience Property added
        self._properties['aud'] = None


    def _get_jwt_payload(self, verification_key):
        self._logger.debug('SSO library path: %s, CCL library path: %s',
                           environ.get('SSOEXT_LIB'), environ.get('SSF_LIB'))

        result_code = self._jwt_validator.loadPEM(
            verification_key)
        if result_code != 0:
            raise RuntimeError(
                'Invalid verification key, result code {0}'.format(result_code))

        self._jwt_validator.checkToken(self._token)
        error_description = self._jwt_validator.getErrorDescription()
        if error_description != '':
            raise RuntimeError(
                'Error in offline validation of access token: {0}, result code {1}'.format(
                    error_description, self._jwt_validator.getErrorRC()))

        jwt_payload = self._jwt_validator.getJWPayload()
        for id_type in ['cid', 'zid']:
            if not id_type in jwt_payload:
                raise RuntimeError(
                    '{0} not contained in access token.'.format(id_type))

        return jwt_payload

    def _set_foreign_mode(self, jwt_payload):
        is_application_plan = '!t' in jwt_payload['cid']
        clientids_match = jwt_payload['cid'] == self._config['clientid']
        zones_match = jwt_payload['zid'] == self._config.get(
            'identityzoneid') or jwt_payload['zid'] == self._config.get('identityzone')

        if clientids_match and (zones_match or is_application_plan):
            self._properties['is_foreign_mode'] = False
            if not is_application_plan:
                self._logger.debug('Client Id and Identity Zone of the access token match'
                                   'with the current application\'s Client Id and Zone.')
            else:
                self._logger.debug('Client Id of the access token (XSUAA application plan)'
                                   ' matches with the current application\'s Client Id.')
        elif self._config.get('trustedclientidsuffix') and jwt_payload['cid'].endswith(self._config['trustedclientidsuffix']):
            self._logger.debug('Token of UAA service plan "broker" received.')
            self._logger.debug(
                'Client Id "%s" of the access token allows consumption by'
                ' the Client Id "%s" of the current application',
                jwt_payload['cid'], self._config['clientid'])
            self._properties['is_foreign_mode'] = False
        elif 'SAP_JWT_TRUST_ACL' in environ:
            self._logger.debug(
                'Client Id "%s" and/or Identity Zone "%s" of the access'
                ' token does not match with the Client Id "%s" and Identity'
                ' Zone "%s" of the current application. Validating token against'
                ' JWT trust ACL (SAP_JWT_TRUST_ACL).', jwt_payload['cid'],
                jwt_payload['zid'], self._config['clientid'],
                self._config.get('identityzoneid') or self._config.get('identityzone'))

            acl_trust = json.loads(environ['SAP_JWT_TRUST_ACL'])
            for acl_entry in acl_trust:
                clientid_match = acl_entry['clientid'] in [
                    '*', jwt_payload['cid']]
                zoneid_match = acl_entry['identityzone'] in [
                    '*', jwt_payload['zid']]
                if clientid_match and zoneid_match:
                    self._properties['is_foreign_mode'] = True
                    self._logger.debug('Foreign token received, but matching entry'
                                       ' in JWT trust ACL (SAP_JWT_TRUST_ACL) found.')
                    break
            if not self._properties['is_foreign_mode']:
                raise RuntimeError(
                    'No match found in JWT trust ACL (SAP_JWT_TRUST_ACL) {0}'.format(
                        acl_trust))
        else:
            raise RuntimeError(
                'Missmatch of client id and/or identityzone id.'
                ' No JWT trust ACL (SAP_JWT_TRUST_ACL) specified in environment.'
                ' Client id of the access token: "{0}",'
                ' identity zone of the access token: "{1}",'
                ' OAuth client id: "{2}",'
                ' application identity zone: "{3}".'.format(
                    jwt_payload['cid'],
                    jwt_payload['zid'],
                    self._config['clientid'],
                    self._config.get('identityzoneid') or self._config.get('identityzone')))

    def _set_grant_type(self, jwt_payload):
        self._properties['grant_type'] = jwt_payload.get('grant_type')
        self._logger.debug(
            'Application received a token of grant type "%s".',
            self.get_grant_type())

    def _set_origin(self, jwt_payload):
        self._properties['origin'] = jwt_payload.get('origin')
        self._logger.debug(
            'Application received a token with user origin "%s".',
            self.get_origin())

    def _set_jwt_expiration(self, jwt_payload):
        jwt_expiration = jwt_payload.get('exp')
        self._logger.debug(
            'Application received a token with exp: %s', jwt_expiration)
        if jwt_expiration:
            self._properties['expiration_date'] = datetime.utcfromtimestamp(
                jwt_expiration)

    def _set_audience(self, jwt_payload):
        self._properties['aud'] = jwt_payload.get('aud') or []
        self._logger.debug(
            'Application received a token with  "%s".',
            self.get_audience())

    def _set_user_info(self, jwt_payload):
        if self.get_grant_type() == constants.GRANTTYPE_CLIENTCREDENTIAL:
            return
        user_info = self._properties['user_info']
        user_info['logon_name'] = jwt_payload.get('user_name')
        if 'ext_attr' in jwt_payload and 'given_name' in jwt_payload['ext_attr']:
            user_info['given_name'] = jwt_payload['ext_attr']['given_name']
        else:
            user_info['given_name'] = jwt_payload.get('given_name')

        if 'ext_attr' in jwt_payload and 'family_name' in jwt_payload['ext_attr']:
            user_info['family_name'] = jwt_payload['ext_attr']['family_name']
        else:
            user_info['family_name'] = jwt_payload.get('family_name')
        user_info['email'] = jwt_payload.get('email')
        self._logger.debug('User info: %s', user_info)

        ext_cxt_container = jwt_payload # old jwt structure
        if 'ext_cxt' in jwt_payload:
            ext_cxt_container = jwt_payload['ext_cxt'] # new jwt structure

        self._properties['saml_token'] = ext_cxt_container.get(
            'hdb.nameduser.saml')
        user_attributes = ext_cxt_container.get('xs.user.attributes') or {}
        self._properties['user_attributes'] = user_attributes
        self._logger.debug('Obtained attributes: %s.', user_attributes)

    def _set_additional_auth_attr(self, jwt_payload):
        additional_auth_attributes = jwt_payload.get('az_attr') or {}
        self._properties['additional_auth_attributes'] = additional_auth_attributes
        self._logger.debug('Obtained additional authentication attributes: %s.',
                           additional_auth_attributes)

    def _set_ext_attr(self, jwt_payload):
        ext_attr = jwt_payload.get('ext_attr')
        if ext_attr:
            self._properties['service_instance_id'] = ext_attr.get('serviceinstanceid')
            self._logger.debug('Obtained serviceinstanceid: %s.', self._properties['service_instance_id'])

            self._properties['subdomain'] = ext_attr.get('zdn')
            self._logger.debug('Obtained subdomain: %s.', self._properties['subdomain'])

            # set subaccount_id to the zone_id as a workaround, if subaccount id is not available.
            if 'subaccountid' in ext_attr and ext_attr.get('subaccountid'):
                self._properties['subaccount_id'] = ext_attr.get('subaccountid')
                self._logger.debug('Obtained subaccountid: %s.', self._properties['subaccount_id'])
            else:
                self._properties['subaccount_id'] = jwt_payload['zid']
                self._logger.debug('Subaccountid not found. Using zid instead: %s.', jwt_payload['zid'])
        else:
            self._properties['subaccount_id'] = jwt_payload['zid']
            self._logger.debug('Subaccountid not found. Using zid instead: %s.', jwt_payload['zid'])

    def _set_scopes(self, jwt_payload):
        self._properties['scopes'] = jwt_payload.get('scope') or []
        self._logger.debug('Obtained scopes: %s.', self._properties['scopes'])

    def _validate_token(self):
        """ Try to retrieve the key from the composed jku if kid is set. Otherwise use configured one."""
        if self._properties['kid']:
            try:
                jku = self._get_jku()
                verification_key = SecurityContextXSUAA.verificationKeyCache.load_key(jku, self._properties['kid'])
                return self._get_jwt_payload(verification_key)
            except (DecodeError, RuntimeError, IOError) as e:
                self._logger.warning("Warning: Could not validate key: {} Will retry with configured key.".format(e))

        if "verificationkey" in self._config:
            self._logger.debug("Validate token with configured verifcation key")
            return self._get_jwt_payload(self._config["verificationkey"])
        else:
            raise RuntimeError("Cannot validate token without verificationkey")

    def _offline_validation(self):
        jwt_payload = self._validate_token()
        # Remove Foreign Mode Support for Now , Support for SAP_JWT_ACL removed
        # self._set_foreign_mode(jwt_payload)
        self._set_grant_type(jwt_payload)
        self._set_origin(jwt_payload)
        self._properties['clientid'] = jwt_payload['cid']
        self._properties['zone_id'] = jwt_payload['zid']
        self._set_jwt_expiration(jwt_payload)
        self._set_user_info(jwt_payload)
        self._set_additional_auth_attr(jwt_payload)
        self._set_ext_attr(jwt_payload)
        self._set_scopes(jwt_payload)
        self._set_audience(jwt_payload)

    def _audience_validation(self):
        audience_validator = JwtAudienceValidator(self._config['clientid'])
        if(self._config['xsappname']):
            audience_validator.configure_trusted_clientId(self._config['xsappname'])
        validation_result = audience_validator.validate_token(self.get_clientid(), self.get_audience(), self._properties['scopes'])

        if validation_result is False:
                raise RuntimeError('Audience Validation Failed')

    def _get_property_of(self, property_name, obj):
        if self.get_grant_type() == constants.GRANTTYPE_CLIENTCREDENTIAL:
            self._logger.debug('Cannot get "%s" with a token of grant type %s',
                               property_name, constants.GRANTTYPE_CLIENTCREDENTIAL)
            return None
        return obj.get(property_name)

    def _get_user_info_property(self, property_name):
        return self._get_property_of(property_name, self._properties['user_info'])

    @deprecation.deprecated(deprecated_in="2.0.11", details="Use the get_zone_id method instead")
    def get_identity_zone(self):
        """:return: The identity zone. """
        return self._properties['zone_id']

    def get_zone_id(self):
        """:return: The zone id. """
        return self._properties['zone_id']

    def get_subaccount_id(self):
        """:return: The subaccount id"""
        return self._properties['subaccount_id']

    def get_subdomain(self):
        """:return: The subdomain that the access token has been issued for. """
        return self._properties['subdomain']

    def get_clientid(self):
        """:return: The client id that the access token has been issued for """
        return self._properties['clientid']

    def get_expiration_date(self):
        """:return: The expiration date of the token. """
        return self._properties['expiration_date']

    def get_logon_name(self):
        """:return: The logon name or None if token is with grant type client credentials. """
        return self._get_user_info_property('logon_name')

    def get_given_name(self):
        """:return: The given name or None if token is with grant type client credentials. """
        return self._get_user_info_property('given_name')

    def get_family_name(self):
        """:return: The family name or None if token is with grant type client credentials. """
        return self._get_user_info_property('family_name')

    def get_email(self):
        """:return: The email or None if token is with grant type client credentials. """
        return self._get_user_info_property('email')

    def get_token(self, namespace, name):
        """
        :param namespace: Namespace used for identifying the different use cases.

        :param name: The name used to differentiate between tokens in a given namespace.

        :return: Token.
        """
        _check_if_valid(namespace, 'namespace')
        _check_if_valid(name, 'name')

        if self.has_attributes() and self.is_in_foreign_mode():
            self._logger.debug('The SecurityContext has been initialized with an access token of a'
                               ' foreign OAuth Client Id and/or Identity Zone. Furthermore, the'
                               ' access token contains attributes. Due to the fact that we want to'
                               ' restrict attribute access to the application that provided the'
                               ' attributes, the getToken function does not return a'
                               ' valid token.')
            return None

        if namespace != constants.SYSTEM:
            self._logger.debug('Namespace "%s" not supported', namespace)
            return None

        if name == constants.JOBSCHEDULER:
            return self._token

        if name == constants.HDB:
            return self._properties.get('saml_token') or self._token

        self._logger.debug('Token name "%s" not supported.', name)
        return None

    def get_hdb_token(self):
        """:return: Token that can be used for contacting the HANA database. """
        return self.get_token(constants.SYSTEM, constants.HDB)

    def get_app_token(self):
        """:return: Application Token that can be used for token forwarding. """
        return self._token

    def check_scope(self, scope):
        """
        :param scope: the scope whose existence is checked against
            the available scopes of the current user.
            Here, the prefix is required, thus the scope string is "globally unique".

        :return: True if the scope is contained in the user's scopes, False otherwise.
        """
        _check_if_valid(scope, 'scope')
        if scope[:len(constants.XSAPPNAMEPREFIX)] == constants.XSAPPNAMEPREFIX:
            scope = scope.replace(
                constants.XSAPPNAMEPREFIX, self._properties['xsappname'] + '.')

        return scope in self._properties['scopes']

    def check_local_scope(self, scope):
        """
        :param scope: the scope whose existence is checked against
            the available scopes of the current user. Here, no prefix is required.

        :return: True if the scope is contained in the user's scopes, False otherwise.
        """
        _check_if_valid(scope, 'scope')
        global_scope = self._properties['xsappname'] + '.' + scope
        return self.check_scope(global_scope)

    def get_grant_type(self):
        """:return: The grant type of the JWT token. """
        return self._properties['grant_type']

    def get_origin(self):
        """
        :return: The user origin. The origin is an alias that refers to a user store in
            which the user is persisted.
        """
        return self._properties['origin']

    def get_audience(self):
        '''
        :return: The user origin. The origin is an alias that refers to a user store in
            which the user is persisted.
        '''
        return self._properties['aud']


    def get_clone_service_instance_id(self):
        """:return: The service instance id of the clone if the XSUAA broker plan is used. """
        return self._properties['service_instance_id']

    def is_in_foreign_mode(self):
        """
        :return: True if the token, that the security context has been
             instantiated with, is a foreign token that was not originally
             issued for the current application, False otherwise.
        """
        return self._properties['is_foreign_mode']

    def _check_uaa_response(self, response, url, grant_type):
        status_code = response.status_code
        if status_code == 200:
            return
        self._logger.debug(
            'Call to %s was not successful, status code: %d, response %s',
            url, status_code, response.text)

        if status_code == 401:
            raise RuntimeError(
                'Call to /oauth/token was not successful (grant_type: {0}).'.format(
                    grant_type) +
                ' Authorization header invalid, requesting client does not have' +
                ' grant_type={0} or no scopes were granted.'.format(constants.GRANTTYPE_JWT_BEARER))
        else:
            raise RuntimeError(
                'Call to /oauth/token was not successful (grant_type: {0}).'.format(
                    grant_type) + ' HTTP status code: {0}'.format(status_code))

    def _user_token_request_content(self, scopes, client_id):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": constants.GRANTTYPE_JWT_BEARER,
            "response_type": "token",
            "client_id": client_id,
            "assertion": self._token,
            'scope': '' if scopes is None else scopes,
        }
        return headers, data

    def _get_user_token(self, url, client_id, scopes, auth, cert):
        headers, data = self._user_token_request_content(scopes, client_id)
        with httpx.Client(cert=cert) as client:
            response = client.post(
                url,
                headers=headers,
                data=data,
                auth=auth,
            )
        self._check_uaa_response(response, url, constants.GRANTTYPE_JWT_BEARER)
        return response.json()['access_token']

    async def _get_user_token_async(self, url, client_id, scopes, auth, cert):
        assert scopes is not None

        headers, data = self._user_token_request_content(scopes, client_id)
        async with httpx.AsyncClient(cert=cert) as client:
            response = await client.post(
                url,
                headers=headers,
                data=data,
                auth=auth,
            )

        self._check_uaa_response(response, url, constants.GRANTTYPE_JWT_BEARER)
        return response.json()["access_token"]

    async def request_token_for_client_async(self, service_credentials, scopes=""):
        """
        :param service_credentials: The credentials of the service as dict.
            The attributes [clientid, certificate, key and url] or [clientid, clientsecret and url] are mandatory.

        :param scopes: comma-separated list of requested scopes for the token,
            e.g. app.scope1,app.scope2. If an empty string is passed, all
            scopes are granted. Note that $XSAPPNAME is not supported as part
            of the scope names.

        :return: Token.
        """
        _check_if_valid(service_credentials, 'service_credentials')
        _check_config(service_credentials)
        use_mtls = True if _has_client_certificate_props(service_credentials) else False
        url = '{}/oauth/token'.format(service_credentials['certurl'] if use_mtls else service_credentials['url'])
        cert_file_name, key_file_name = None, None
        try:
            if use_mtls:
                cert_file_name, key_file_name = _create_cert_and_key_files(service_credentials['certificate'],
                                                                           service_credentials.get('key'))
            return await self._get_user_token_async(url, service_credentials['clientid'], scopes,
                                        auth=None if use_mtls else (service_credentials['clientid'],
                                                                    service_credentials['clientsecret']),
                                        cert=(cert_file_name, key_file_name) if use_mtls else None)

        finally:
            _delete_cert_and_key_files(cert_file_name, key_file_name)

    def request_token_for_client(self, service_credentials, scopes=""):
        """
        :param service_credentials: The credentials of the service as dict.
            The attributes [clientid, certificate, key and url] or [clientid, clientsecret and url] are mandatory.

        :param scopes: comma-separated list of requested scopes for the token,
            e.g. app.scope1,app.scope2. If an empty string is passed, all
            scopes are granted. Note that $XSAPPNAME is not supported as part
            of the scope names.

        :return: Token.
        """
        _check_if_valid(service_credentials, 'service_credentials')
        _check_config(service_credentials)
        use_mtls = True if _has_client_certificate_props(service_credentials) else False
        url = '{}/oauth/token'.format(service_credentials['certurl'] if use_mtls else service_credentials['url'])
        cert_file_name, key_file_name = None, None
        try:
            if use_mtls:
                cert_file_name, key_file_name = _create_cert_and_key_files(service_credentials['certificate'],
                                                                           service_credentials.get('key'))
            return self._get_user_token(url, service_credentials['clientid'], scopes,
                                        auth=None if use_mtls else (service_credentials['clientid'],
                                                                    service_credentials['clientsecret']),
                                        cert=(cert_file_name, key_file_name) if use_mtls else None)

        finally:
            _delete_cert_and_key_files(cert_file_name, key_file_name)

    def has_attributes(self):
        """
        :return: True if the token contains any xs user attributes, False otherwise.
            Not available for tokens of grant_type client_credentials.
        """
        has_user_attributes = self._get_property_of(
            'user_attributes', self._properties)
        if has_user_attributes is not None:
            return bool(has_user_attributes)
        return None

    def get_attribute(self, name):
        """
        :param name: The name of the attribute that is requested.

        :return: The attribute exactly as it is contained in the access token.
            If no attribute with the given name is contained in the access token, None is returned.
            If the token, that the security context has been instantiated with,
            is a foreign token (meaning that the OAuth client contained in the
            token and the OAuth client of the current application do not match),
            None is returned regardless of whether the requested attribute is contained
            in the token or not.
        """
        _check_if_valid(name, 'name')
        has_attributes = self.has_attributes()
        if not has_attributes:
            if has_attributes is False:
                self._logger.debug(
                    'The access token contains no user attributes.')
            return None

        if self.is_in_foreign_mode():
            self._logger.debug('The SecurityContext has been initialized with an access token of a'
                               ' foreign OAuth Client Id and/or Identity Zone. Furthermore, the'
                               ' access token contains attributes. Due to the fact that we want to'
                               ' restrict attribute access to the application that provided the'
                               ' attributes, the getAttribute function does not return any'
                               ' attributes.')
            return None

        if name not in self._properties['user_attributes']:
            self._logger.debug(
                'No attribute "%s" found for user "%s".', name, self.get_logon_name())
            return None
        return self._properties['user_attributes'][name]

    def get_additional_auth_attribute(self, name):
        """
        :param name: The name of the additional authentication attribute that is requested.

        :return: The additional authentication attribute exactly as it is contained in
            the access token. If no attribute with the given name is contained in the
            access token, None is returned. Note that additional authentication attributes
            are also returned in foreign mode (in contrast to getAttribute).
        """
        _check_if_valid(name, 'name')
        if not bool(self._properties['additional_auth_attributes']):
            self._logger.debug(
                'The access token contains no additional authentication attributes.')
            return None

        if not name in self._properties['additional_auth_attributes']:
            self._logger.debug(
                'No attribute "%s" found as additional authentication attribute.', name)
            return None

        return self._properties['additional_auth_attributes'][name]
