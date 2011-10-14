
"""
Tests for the twistd application plugin to run a Pantheon SSH server.
"""

from zope.interface.verify import verifyObject

from twisted.python.usage import UsageError
from twisted.python.filepath import FilePath
from twisted.trial.unittest import TestCase
from twisted.plugin import IPlugin
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.application.service import IServiceMaker, MultiService
from twisted.application.internet import StreamServerEndpointService
from twisted.conch.ssh.factory import SSHFactory
from twisted.conch.ssh.keys import Key
from twisted.cred.credentials import IUsernamePassword, ISSHPrivateKey

from twisted.plugins.pantheonssh_tap import pantheonssh

from pantheonssh.realm import PantheonRealm
from pantheonssh.checker import PantheonHTTPChecker

HOST_KEY_PATH = FilePath(__file__).sibling('id_rsa').path
SSL_KEY = FilePath(__file__).sibling('cakey.pem')
SSL_CERT = FilePath(__file__).sibling('cacert.pem')

class PluginTests(TestCase):
    """
    Tests for the L{IServiceMaker} plugin definition that lets twistd run a
    Pantheon SSH server.
    """
    def test_interface(self):
        """
        L{pantheonssh} provides L{IServiceMaker} and L{IPlugin}.
        """
        self.assertTrue(verifyObject(IServiceMaker, pantheonssh))
        self.assertTrue(verifyObject(IPlugin, pantheonssh))


    def test_description(self):
        """
        L{pantheonssh} defines a name and description for the plugin.
        """
        self.assertIsInstance(pantheonssh.name, str)
        self.assertIsInstance(pantheonssh.description, str)


    def test_options(self):
        """
        An instance of L{pantheonssh.options} can parse a command line argument
        list for the address of a backend authentication server to use.
        """
        options = pantheonssh.options()
        options.parseOptions([
                '--auth-host', 'example.com', '--auth-port', '1234',
                '--host-key', HOST_KEY_PATH, '--listen', 'tcp:22',
                '--client-key', SSL_KEY.path,
                '--client-cert', SSL_CERT.path])
        self.assertEqual(options['auth-host'], 'example.com')
        self.assertEqual(options['auth-port'], 1234)
        self.assertEqual(options['host-key'], Key.fromFile(HOST_KEY_PATH))

        self.assertEqual(options['client-key'], SSL_KEY)
        self.assertEqual(options['client-cert'], SSL_CERT)
        self.assertEqual(1, len(options['listen']))
        self.assertIsInstance(options['listen'][0], TCP4ServerEndpoint)


    def test_required(self):
        """
        If any of I{--auth-host}, I{--auth-port}, I{--host-key}, or I{--listen}
        is not given, L{pantheonssh.options.parseOptions} raises L{UsageError}.
        """
        requiredOptions = [
            ('--auth-host', 'example.com'),
            ('--auth-port', '1234'),
            ('--host-key', HOST_KEY_PATH),
            ('--listen', 'tcp:22'),
            ('--client-key', SSL_KEY.path),
            ('--client-cert', SSL_CERT.path),
            ]
        for i in range(len(requiredOptions)):
            options = pantheonssh.options()
            use = []
            for n, opt in enumerate(requiredOptions):
                # Skip one of them
                if n != i:
                    use.extend(opt)
            self.assertRaises(UsageError, options.parseOptions, use)


    def test_badKey(self):
        """
        If a non-existent or unparseable host key file is given, L{UsageError}
        is raised.
        """
        options = pantheonssh.options()
        nonexistent = self.mktemp()
        self.assertRaises(
            UsageError, options.parseOptions,
            ['--auth-host', 'example.com', '--auth-port', '1234',
             '--listen', 'tcp:22', '--host-key', nonexistent,
             '--client-key', SSL_KEY.path, '--client-cert', SSL_CERT.path])
        invalid = self.mktemp()
        FilePath(invalid).setContent("some random junk")
        self.assertRaises(
            UsageError, options.parseOptions,
            ['--auth-host', 'example.com', '--auth-port', '1234',
             '--listen', 'tcp:22', '--host-key', invalid,
             '--client-key', SSL_KEY.path, '--client-cert', SSL_CERT.path])


    def test_makeService(self):
        """
        C{pantheonssh.makeService} accepts an instance of L{pantheonssh.options}
        and returns a service which listens for SSH connections and
        authenticates them using the backend server specified by those options.
        """
        options = pantheonssh.options()
        options['auth-host'] = 'example.com'
        options['auth-port'] = 1234
        options['host-key'] = Key.fromFile(HOST_KEY_PATH)
        options['listen'] = [TCP4ServerEndpoint(None, None)]
        service = pantheonssh.makeService(options)
        self.assertIsInstance(service, MultiService)
        self.assertEqual(1, len(service.services))
        service = service.services[0]
        self.assertIsInstance(service, StreamServerEndpointService)
        self.assertIsInstance(service.factory, SSHFactory)
        realm = service.factory.portal.realm
        self.assertIsInstance(realm, PantheonRealm)
        self.assertEqual(realm._host, 'example.com')
        self.assertEqual(realm._port, 1234)
        checkers = service.factory.portal.checkers
        self.assertIdentical(checkers[IUsernamePassword], checkers[ISSHPrivateKey])
        self.assertIsInstance(checkers[ISSHPrivateKey], PantheonHTTPChecker)
        self.assertEqual(checkers[ISSHPrivateKey]._host, 'example.com')
        self.assertEqual(checkers[ISSHPrivateKey]._port, 1234)
