class JwtAudienceValidator(object):
    '''
     Validates if the jwt access token is intended for the OAuth2 client of this
     application. The aud (audience) claim identifies the recipients the JWT is
    issued for.

    Validates whether there is one audience that matches one of the configured
    OAuth2 client ids.
    '''

    DOT = "."

    def __init__(self, clientid):
        self._clientid = clientid
        self._trusted_clientids = set()
        self.trusted_clientids = clientid
        self._is_foreign_mode = False


    @property
    def trusted_clientids(self):
        return self._trusted_clientids

    @trusted_clientids.setter
    def trusted_clientids(self, clientid):
        if clientid:
            self._trusted_clientids.add(clientid)

    @property
    def is_foreign_mode(self):
        return False

    @is_foreign_mode.setter
    def is_foreign_mode(self, foreignmode):
        self._is_foreign_mode = foreignmode

    @property
    def clientid(self):
        return self._clientid

    @clientid.setter
    def clientid(self, clientId):
        self._clientid = clientId

    def configure_trusted_clientId(self, client_id):
        if client_id:
            self.trusted_clientids.add(client_id)

    def validate_token(self, clientId_from_token=None, audiences_from_token= [], scopes_from_token = []):
        self.is_foreign_mode = False
        allowed_audiences = self.extract_audiences_from_token(audiences_from_token, scopes_from_token, clientId_from_token)
        if (self.validate_same_clientId(clientId_from_token) == True or
                self.validate_audience_of_xsuaabrokerclone(allowed_audiences) == True or
                self.validate_default(allowed_audiences)==True):
            return True
        else:
            return False


    def extract_audiences_from_token(self, audiences_from_token= [], scopes_from_token= [], clientid_from_token=None):
        '''
        Extracts Audience From Token
        '''
        audiences = []
        token_audiences = audiences_from_token
        for audience in token_audiences:
            if audience.find(self.DOT) > -1:
         # CF UAA derives the audiences from the scopes.
         # In case the scopes contains namespaces, these needs to be removed.
             audience = audience[0:audience.find(self.DOT)].strip()
             if audience and (audience not in audiences):
                audiences.append(audience)
            else:
                audiences.append(audience)

        if len(audiences) == 0:

            for scope in scopes_from_token:

                if scope.find(self.DOT) > -1:
                  audience = scope[0 :scope.find(self.DOT)].strip()
                  if audience :
                    if (audience not in audiences):
                        audiences.append(audience)

            if (clientid_from_token and (clientid_from_token not in audiences)):
                audiences.append(clientid_from_token)

        return audiences

    def validate_same_clientId(self, clientid_from_token):
        if clientid_from_token == self.clientid:
            return True
        else:
            return False

    def validate_audience_of_xsuaabrokerclone(self, allowed_audiences):
        for configured_clientid in self.trusted_clientids:
            if ("!b") in configured_clientid:
             # isBrokerClientId
                for audience in allowed_audiences:
                    if (audience.endswith("|" + configured_clientid)):
                        return True
        self.is_foreign_mode=True
        return False

    def validate_default(self, allowedAudiences):
        for configuredClientId in self.trusted_clientids:
            if configuredClientId in allowedAudiences:
                return True

        return False
