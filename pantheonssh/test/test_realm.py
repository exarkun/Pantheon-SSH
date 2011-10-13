
"""
Tests for L{pantheonssh.realm}.
"""

from zope.interface.verify import verifyObject

from twisted.internet import reactor
from twisted.trial.unittest import TestCase
from twisted.cred.portal import IRealm
from twisted.conch.interfaces import IConchUser

from pantheonssh.realm import PantheonSite, PantheonRealm
from pantheonssh.test.fakebackend import FakeBackendMixin


class PantheonRealmTests(FakeBackendMixin, TestCase):
    """
    Tests for L{PantheonRealm} which authorizes clients by creating suitable
    local user objects for them.
    """
    def setUp(self):
        """
        Create a L{PantheonRealm} pointed at a mock authentication service
        with some simple site and user information.
        """
        FakeBackendMixin.setUp(self)
        self.realm = PantheonRealm(
            reactor, '127.0.0.1', self.server.port.getHost().port)


    def test_interface(self):
        """
        A L{PantheonRealm} instance provides L{IRealm}.
        """
        self.assertTrue(verifyObject(IRealm, self.realm))


    def test_requestAvatar(self):
        """
        L{PantheonRealm.requestAvatar} returns a L{Deferred} which fires with a
        L{PantheonSite} configured with command execution parameters specific to
        the site requested.
        """
        d = self.realm.requestAvatar('example.com', None, IConchUser)
        def cbAvatar(avatar):
            self.assertIsInstance(avatar, PantheonSite)
            self.assertEqual(self.cwd, avatar.cwd)
            self.assertEqual(self.uid, avatar.uid)
        d.addCallback(cbAvatar)
        return d
