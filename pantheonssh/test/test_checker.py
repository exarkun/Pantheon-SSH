
"""
Tests for L{pantheonssh.checker}.
"""

import json

from zope.interface.verify import verifyObject

from twisted.internet import reactor

from twisted.python.filepath import FilePath
from twisted.trial.unittest import TestCase
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import (
    IUsernamePassword, ISSHPrivateKey, UsernamePassword, SSHPrivateKey)
from twisted.application.service import Service
from twisted.web.http import NOT_FOUND
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.conch.error import ValidPublicKey
from twisted.conch.ssh.keys import Key

from pantheonssh.checker import PantheonHTTPChecker


class MockPantheonAuthResource(Resource):
    """
    The following resources are implemented:

        /sites/<site name>/check-password

          POST a JSON encoded string giving a plaintext password.  The response
          is a JSON encoded boolean indicating whether the password is valid for
          the site in the URL.

        /sites/<site name>/check-key

          POST a JSON encoded string giving an OpenSSH-style public key string.
          The response is a JSON encoded boolean indicating whether the password
          is valid for the site in the URL.
    """
    isLeaf = True

    def __init__(self, sites, passwords, keys):
        Resource.__init__(self)
        self.sites = sites
        self.passwords = passwords
        self.keys = keys


    def render_POST(self, request):
        if request.postpath[0] == 'sites':
            if request.postpath[1] in self.sites:
                if request.postpath[2] == 'check-password':
                    password = json.loads(request.content.read())
                    valid = self._checkPassword(request.postpath[1], password)
                    return json.dumps(valid)
                elif request.postpath[2] == 'check-key':
                    publicKey = json.loads(request.content.read())
                    valid = self._checkPublicKey(request.postpath[1], publicKey)
                    return json.dumps(valid)
        request.setResponseCode(NOT_FOUND)
        return '404'


    def render_GET(self, request):
        request.setResponseCode(NOT_FOUND)
        return '404'


    def _checkPassword(self, site, password):
        """
        Determine whether a password is valid for a site by comparing it to the
        password for each user which is allowed access to the site.  Return
        C{True} if it is valid, C{False} otherwise.
        """
        return any(
            self.passwords[user] == password for user in self.sites[site])


    def _checkPublicKey(self, site, publicKey):
        """
        Determine whether a key is valid for a site by comparing the public blob
        representation to the blob for the key for each user which is allowed
        access to the site.  Return C{True} if it is valid, C{False} otherwise.
        """
        return any(
            self.keys[user].public().toString('openssh') == publicKey
            for user in self.sites[site])



class MockPantheonAuthServer(Service):
    """
    A web service which simulates the Pantheon authentication and authorization
    HTTP REST API.  See L{MockPantheonAuthResource} for details.
    """
    def __init__(self, reactor, sites, passwords, keys):
        self.reactor = reactor
        self.sites = sites
        self.passwords = passwords
        self.keys = keys


    def startService(self):
        Service.startService(self)
        self.resource = MockPantheonAuthResource(
            self.sites, self.passwords, self.keys)
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
        keyString = FilePath(__file__).sibling('id_rsa').getContent()
        self.privateKey = Key.fromString(keyString)
        self.server = MockPantheonAuthServer(
            reactor, sites={self.site: [self.username]},
            passwords={self.username: self.password},
            keys={self.username: self.privateKey},
            )
        self.server.startService()
        self.addCleanup(self.server.stopService)
        self.checker = PantheonHTTPChecker(
            reactor, '127.0.0.1', self.server.port.getHost().port)


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
        credentials = UsernamePassword(self.site, 'bad wrong password')
        d = self.checker.requestAvatarId(credentials)
        return self.assertFailure(d, UnauthorizedLogin)


    def test_invalidPublicKey(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{UnauthorizedLogin} when
        passed an L{ISSHPrivateKey} credentials object which does not correspond
        to any valid user.
        """
        blob = self.privateKey.blob()
        blob = blob[:64] + blob[:63:-1]
        credentials = SSHPrivateKey(
            self.site, 'sha1', blob, 'some random bytes', None)
        return self.assertFailure(
            self.checker.requestAvatarId(credentials), UnauthorizedLogin)


    def test_misformattedPublicKey(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{UnauthorizedLogin} when
        passed an L{ISSHPrivateKey} credentials object with an unparseable key
        blob.
        """
        credentials = SSHPrivateKey(
            self.site, 'sha1', 'hello, world', 'some random bytes', None)
        return self.assertFailure(
            self.checker.requestAvatarId(credentials), UnauthorizedLogin)


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
        credentials = UsernamePassword(self.site, self.password)
        d = self.checker.requestAvatarId(credentials)
        d.addCallback(self.assertEqual, self.site)
        return d


    def test_publicKeyValidityCheck(self):
        """
        A user may determine the validity of a public key by presenting it
        without using it to sign any data.  If the site represented by
        L{ISSHPrivateKey.user} is accessible to a user for whom that public key
        is valid, L{PantheonHTTPChecker.requestAvatarId} fails with
        L{ValidPublicKey}.
        """
        credentials = SSHPrivateKey(
            self.site, 'sha1', self.privateKey.blob(), None, None)
        d = self.checker.requestAvatarId(credentials)
        return self.assertFailure(d, ValidPublicKey)


    def test_publicKeyWithSignature(self):
        """
        A user may authenticate for a site by using that site as the username
        and a public key associated with a user who is allowed access to that
        site.  When L{PantheonHTTPChecker.requestAvatarId} is presented with
        such an L{ISSHPrivateKey} credentials object, it returns the site
        identifier.
        """
        data = "here are the bytes, they are for you, and they are random"
        credentials = SSHPrivateKey(
            self.site, 'sha1', self.privateKey.blob(), data,
            self.privateKey.sign(data))
        d = self.checker.requestAvatarId(credentials)
        d.addCallback(self.assertEqual, self.site)
        return d
