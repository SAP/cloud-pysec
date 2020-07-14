class JwtAudienceValidator(object):
    '''
     Validates if the jwt access token is intended for the OAuth2 client of this
     application. The aud (audience) claim identifies the recipients the JWT is
    issued for.

    Validates whether there is one audience that matches one of the configured
    OAuth2 client ids.
    '''

    DOT = "."

    def __init__(self, clientId):
        self._clientId = clientId
        self._clientIds = set()
        self.clientIds = clientId
        self._foreignmode = False


    @property
    def clientIds(self):
        return self._clientIds

    @clientIds.setter
    def clientIds(self, clientId):
        if clientId:
            self._clientIds.add(clientId)

    @property
    def foreignmode(self):
        return self._foreignmode

    @foreignmode.setter
    def foreignmode(self, foreignmode):
        self._foreignmode = foreignmode

    @property
    def clientId(self):
        return self._clientId

    @clientId.setter
    def clientId(self, clientId):
        self._clientId = clientId

    def validateToken(self,audiencesFromToken, scopesFromToken, clientIdFromToken):
        self.foreignMode = False
        allowedAudiences = self.extractAudiencesFromToken(audiencesFromToken, scopesFromToken, clientIdFromToken)
        if (self.validateSameClientId(clientIdFromToken) == True or
                self.validateAudienceOfXsuaaBrokerClone(allowedAudiences) == True or
                self.validateDefault(allowedAudiences)==True):
            return True


    def extractAudiencesFromToken(self, audiencesFromToken, scopesFromToken, clientIdFromToken):
        audiences = []
        tokenAudiences = audiencesFromToken

        for audience in tokenAudiences:
            if audience.index(self.DOT) > -1:
         # CF UAA derives the audiences from the scopes.
         # In case the scopes contains namespaces, these needs to be removed.
             audience = audience.substring(0, audience.indexOf(self.DOT)).trim();
             if audience and (audience not in audiences):
                audiences.push(audience)
            else:
                audiences.push(audience)

        if len(audiences) == 0:

            for scope in scopesFromToken:

                if scope.index(self.DOT) > -1:
                  audience = scope.substring(0, scope.indexOf(self.DOT)).trim();
                if audience and (audience not in audiences):
                    audiences.push(audience)

            if (clientIdFromToken and (clientIdFromToken not in audiences)):
                audiences.push(clientIdFromToken)

        return audiences

    def validateSameClientId(self, clientIdFromToken):
        if clientIdFromToken == self.clientId:
            return True
        else:
            return False

    def validateAudienceOfXsuaaBrokerClone(self, allowedAudiences):
        for configuredClientId in self.clientIds:
            if configuredClientId.contains("!b") :
             # isBrokerClientId
                for audience in allowedAudiences:
                    if (audience.endswith("|" + configuredClientId)):
                        return True

        return False

