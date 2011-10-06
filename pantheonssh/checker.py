# -*- test-case-name: pantheonssh.test.test_checker -*-

"""
This module implements a L{twisted.cred} checker which can authenticate clients
using passwords or SSH key pairs.
"""

from zope.interface import implements

from twisted.cred.error import UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword, ISSHPrivateKey

class PantheonHTTPChecker(object):
    """
    This is a checker which validates credentials by making HTTP requests to a
    REST API which sits on top of the actual credentials data.

    @ivar _host: The hostname or dotted-quad IPv4 address of the HTTP server
        against which to authenticate.

    @ivar _port: The port number of the HTTP server against which to
        authenticate.
    """
    implements(ICredentialsChecker)

    credentialInterfaces = [IUsernamePassword, ISSHPrivateKey]

    def __init__(self, host, port):
        self._host = host
        self._port = port

    def requestAvatarId(self, credentials):
        """
        Check the given credentials and return a suitable user identifier if
        they are valid.
        """
        if IUsernamePassword.providedBy(credentials):
            raise UnauthorizedLogin()
        if ISSHPrivateKey.providedBy(credentials):
            raise UnauthorizedLogin()
        raise NotImplementedError()