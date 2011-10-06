
"""
Tests for L{pantheonssh.checker}.
"""

from zope.interface.verify import verifyObject

from twisted.internet import reactor

from twisted.trial.unittest import TestCase
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import (
    IUsernamePassword, ISSHPrivateKey, UsernamePassword, SSHPrivateKey)
from twisted.application.service import Service
from twisted.web.http import NOT_FOUND
from twisted.web.resource import Resource
from twisted.web.server import Site

from pantheonssh.checker import PantheonHTTPChecker


class MockPantheonAuthResource(Resource):
    """
    The following resources are implemented:

        /sites/<site name>/check-password

          POST a JSON encoded string giving a plaintext password.  The response
          is a JSON encoded boolean indicating whether the password is valid for
          the site in the URL.
    """
    isLeaf = True

    def __init__(self, sites, users):
        Resource.__init__(self)
        self.sites = sites
        self.users = users


    def render_POST(self, request):
        if request.postpath[0] == ['sites']:
            if request.postpath[1] in self.sites:
                if request.postpath[2] == 'check-password':
                    password = json.loads(request.content.read())
                    valid = self._checkPassword(request.postpath[1], password)
                    return json.dumps(valid)
        request.setResponseCode(NOT_FOUND)
        return '404'


    def render_GET(self, request):
        request.setResponseCode(NOT_FOUND)
        return '404'



class MockPantheonAuthServer(Service):
    """
    A web service which simulates the Pantheon authentication and authorization
    HTTP REST API.  See L{MockPantheonAuthResource} for details.
    """
    def __init__(self, reactor, sites, users):
        self.reactor = reactor
        self.sites = sites
        self.users = users


    def startService(self):
        Service.startService(self)
        self.resource = MockPantheonAuthResource(self.sites, self.users)
        self.factory = Site(self.resource)
        self.port = self.reactor.listenTCP(0, self.factory)


    def stopService(self):
        Service.stopService(self)
        return self.port.stopListening()



class PantheonHTTPCheckerTests(TestCase):
    """
    Tests for L{PantheonHTTPChecker}, a credentials checker for key pairs and
    passwords which verifies credentials against an HTTP API.
    """
    def setUp(self):
        """
        Create a L{PantheonHTTPChecker} pointed at a mock authentication service
        with some simple site and user information.
        """
        self.site = 'example.com'
        self.username = 'alice'
        self.password = 'correct password'
        self.server = MockPantheonAuthServer(
            reactor, sites={self.site: [self.username]},
            users={self.username: self.password})
        self.server.startService()
        self.addCleanup(self.server.stopService)
        self.checker = PantheonHTTPChecker(
            '127.0.0.1', self.server.port.getHost().port)


    def test_interface(self):
        """
        An instance of L{PantheonHTTPChecker} provides L{ICredentialsChecker}.
        """
        self.assertTrue(verifyObject(ICredentialsChecker, self.checker))


    def test_credentialInterfaces(self):
        """
        L{PantheonHTTPChecker} declares that it can check credentials of types
        L{IUsernamePassword} and L{ISSHPrivateKey}.
        """
        self.assertIn(
            IUsernamePassword, self.checker.credentialInterfaces)
        self.assertIn(
            ISSHPrivateKey, self.checker.credentialInterfaces)


    def test_invalidPassword(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{UnauthorizedLogin} when
        passed an L{IUsernamePassword} credentials object which does not
        correspond to any valid user.
        """
        credentials = UsernamePassword(self.username, 'bad wrong password')
        self.assertRaises(
                UnauthorizedLogin, self.checker.requestAvatarId, credentials)


    def test_invalidPublicKey(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{UnauthorizedLogin} when
        passed an L{ISSHPrivateKey} credentials object which does not correspond
        to any valid user.
        """
        credentials = SSHPrivateKey(
            self.site, 'sha1', 'hello, world', 'some random bytes', None)
        self.assertRaises(
                UnauthorizedLogin, self.checker.requestAvatarId, credentials)


    def test_invalidCredentials(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{NotImplementedError}
        when passed a credentials object which provides neither
        L{IUsernamePassword} nor L{ISSHPrivateKey}.
        """
        self.assertRaises(
                NotImplementedError, self.checker.requestAvatarId, object())


    def test_password(self):
        """
        If presented with an L{IUsernamePassword} where the username portion
        identifies a site and the password portion gives a password which is a
        valid password for a user associated with that site,
        L{PantheonHTTPChecker} returns the site's unique identifier as the
        avatar identifier.  L{PantheonHTTPChecker} determines the validity of
        the password by issuing a request to the HTTP server with which it is
        configured.
        """
        credentials = UsernamePassword(self.username, self.password)
        d = self.checker.requestAvatarId(credentials)
        d.addCallback(self.assertEqual, site)
        return d
