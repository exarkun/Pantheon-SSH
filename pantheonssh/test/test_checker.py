
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
from twisted.conch.error import ValidPublicKey

from pantheonssh.checker import PantheonHTTPChecker

from pantheonssh.test.fakebackend import FakeBackendMixin
from pantheonssh.test.test_tap import SSL_KEY, SSL_CERT


class PantheonHTTPCheckerTests(FakeBackendMixin, TestCase):
    """
    Tests for L{PantheonHTTPChecker}, a credentials checker for key pairs and
    passwords which verifies credentials against an HTTP API.
    """
    def setUp(self):
        """
        Create a L{PantheonHTTPChecker} pointed at a mock authentication service
        with some simple site and user information.
        """
        FakeBackendMixin.setUp(self)
        self.checker = PantheonHTTPChecker(
            reactor, '127.0.0.1', self.server.port.getHost().port,
            SSL_KEY.path, SSL_CERT.path)


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
