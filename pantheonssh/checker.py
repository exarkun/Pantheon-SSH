# -*- test-case-name: pantheonssh.test.test_checker -*-

"""
This module implements a L{twisted.cred} checker which can authenticate clients
using passwords or SSH key pairs.
"""

import json

from zope.interface import implements

from twisted.cred.error import UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword, ISSHPrivateKey
from twisted.web.http_headers import Headers
from twisted.web.client import Agent

from pantheonssh._httpclient import StringProducer, readBody


class PantheonHTTPChecker(object):
    """
    This is a checker which validates credentials by making HTTP requests to a
    REST API which sits on top of the actual credentials data.

    @ivar _reactor: An L{IReactorSSL} provider to use to issue HTTP requests.

    @ivar _host: The hostname or dotted-quad IPv4 address of the HTTP server
        against which to authenticate.

    @ivar _port: The port number of the HTTP server against which to
        authenticate.
    """
    implements(ICredentialsChecker)

    credentialInterfaces = [IUsernamePassword, ISSHPrivateKey]

    def __init__(self, reactor, host, port):
        self._reactor = reactor
        self._host = host
        self._port = port


    def requestAvatarId(self, credentials):
        """
        Check the given credentials and return a suitable user identifier if
        they are valid.
        """
        if IUsernamePassword.providedBy(credentials):
            return self._checkPassword(credentials)
        if ISSHPrivateKey.providedBy(credentials):
            raise UnauthorizedLogin()
        raise NotImplementedError()


    def _checkPassword(self, credentials):
        """
        Check a L{IUsernamePassword} credentials-based authentication attempt.
        Treat the username as a site identifier.  Ask the backend HTTP server if
        the password given is valid for that site.
        """
        agent = Agent(self._reactor)

        # XXX Add some direct unit tests for this - including proper quoting of
        # the site identifier
        url = 'http://%s:%d/sites/%s/check-password' % (
            self._host, self._port, credentials.username)

        body = StringProducer(json.dumps(credentials.password))

        response = agent.request('POST', url, Headers(), body)
        def cbResponse(response):
            # XXX Is this is right check to verify the server is giving us a
            # good response?
            if response.code == 200:
                return readBody(response)
            # XXX Log this unexpected error
            raise UnauthorizedLogin()
        body = response.addCallback(cbResponse)
        def cbBody(body):
            valid = json.loads(body)
            if valid:
                return credentials.username
            raise UnauthorizedLogin()
        result = body.addCallback(cbBody)
        return result
