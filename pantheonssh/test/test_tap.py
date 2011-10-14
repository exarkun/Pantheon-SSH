
"""
Tests for the twistd application plugin to run a Pantheon SSH server.
"""

from twisted.trial.unittest import TestCase

from twisted.plugins.pantheonssh_tap import PantheonSSH


class PluginTests(TestCase):
    """
    Tests for the L{IServiceMaker} plugin definition that lets twistd run a
    Pantheon SSH server.
    """
    def test_interface(self):
        """
        L{PantheonSSH} provides L{IServiceMaker} and L{IPlugin}.
        """
        self.assertTrue(verifyObject(IServiceMaker, PantheonSSH))
        self.assertTrue(verifyObject(IPlugin, PantheonSSH))
