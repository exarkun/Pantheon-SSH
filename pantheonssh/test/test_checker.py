
"""
Tests for L{pantheonssh.checker}.
"""

from zope.interface.verify import verifyObject

from twisted.trial.unittest import TestCase
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import (
    IUsernamePassword, ISSHPrivateKey, UsernamePassword, SSHPrivateKey)

from pantheonssh.checker import PantheonHTTPChecker


class PantheonHTTPCheckerTests(TestCase):
    """
    Tests for L{PantheonHTTPChecker}, a credentials checker for key pairs and
    passwords which verifies credentials against an HTTP API.
    """
    def test_interface(self):
        """
        An instance of L{PantheonHTTPChecker} provides L{ICredentialsChecker}.
        """
        self.assertTrue(verifyObject(ICredentialsChecker, PantheonHTTPChecker()))


    def test_credentialInterfaces(self):
        """
        L{PantheonHTTPChecker} declares that it can check credentials of types
        L{IUsernamePassword} and L{ISSHPrivateKey}.
        """
        self.assertIn(
            IUsernamePassword, PantheonHTTPChecker.credentialInterfaces)
        self.assertIn(
            ISSHPrivateKey, PantheonHTTPChecker.credentialInterfaces)


    def test_invalidPassword(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{UnauthorizedLogin} when
        passed an L{IUsernamePassword} credentials object which does not
        correspond to any valid user.
        """
        checker = PantheonHTTPChecker()
        credentials = UsernamePassword('alice', 'bad password')
        self.assertRaises(UnauthorizedLogin, checker.requestAvatarId, credentials)


    def test_invalidPublicKey(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{UnauthorizedLogin} when
        passed an L{ISSHPrivateKey} credentials object which does not correspond
        to any valid user.
        """
        checker = PantheonHTTPChecker()
        credentials = SSHPrivateKey(
            'alice', 'sha1', 'hello, world', 'some random bytes', None)
        self.assertRaises(UnauthorizedLogin, checker.requestAvatarId, credentials)


    def test_invalidCredentials(self):
        """
        L{PantheonHTTPChecker.requestAvatarId} raises L{NotImplementedError}
        when passed a credentials object which provides neither
        L{IUsernamePassword} nor L{ISSHPrivateKey}.
        """
        checker = PantheonHTTPChecker()
        self.assertRaises(NotImplementedError, checker.requestAvatarId, object())

