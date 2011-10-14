# -*- test-case-name: pantheonssh.test.test_tap -*-

"""
Implementation of the twistd plugins for the Pantheon SSH server.
"""

__all__ = ["Options", "makeService"]

from OpenSSL.SSL import FILETYPE_PEM

from twisted.python.filepath import FilePath
from twisted.python.usage import UsageError, Options
from twisted.internet.ssl import KeyPair, PrivateCertificate
from twisted.internet.endpoints import serverFromString
from twisted.application.service import MultiService
from twisted.application.internet import StreamServerEndpointService
from twisted.conch.ssh.factory import SSHFactory
from twisted.conch.ssh.keys import BadKeyError, Key
from twisted.cred.portal import Portal

from pantheonssh.checker import PantheonHTTPChecker
from pantheonssh.realm import PantheonRealm

class Options(Options):
    """
    Command-line argument parsing definitions for the Pantheon SSH server.
    """
    optParameters = [
        ("auth-host", None, None,
         "Hostname or IP address of backend authentication server"),
        ("auth-port", None, None,
         "Port number of backend authentication server", int),
        ("host-key", None, None, "Path to host private key", FilePath),
        ('client-key', None, None,
         "Path to PEM-format client key to use with HTTPS requests to the "
         "authentication server.", FilePath),
        ('client-cert', None, None,
         "Path to PEM-format client certificate to use with HTTPS requests to "
         "the authentication server.", FilePath),
        ]

    def opt_listen(self, description):
        """
        A string endpoint description on which to listen for SSH connections.
        """
        from twisted.internet import reactor

        endpoint = serverFromString(reactor, description)
        self.setdefault("listen", []).append(endpoint)


    def postOptions(self):
        """
        Verify the configuration is usable.
        """
        for required in ["auth-host", "auth-port", "host-key", "client-key",
                         "client-cert"]:
            if self[required] is None:
                raise UsageError("--%s option is required" % (required,))
        try:
            self["host-key"] = Key.fromFile(self["host-key"].path)
        except (IOError, BadKeyError), e:
            raise UsageError("Cannot load host key: %s" % (e,))

        if "listen" not in self:
            raise UsageError(
                "At least one listen address must be given using --listen")



def makeService(options):
    """
    Construct a Pantheon SSH service.
    """
    from twisted.internet import reactor

    factory = SSHFactory()
    key = options["host-key"]
    factory.privateKeys = {key.sshType(): key}
    factory.publicKeys = {key.sshType(): key.public()}
    realm = PantheonRealm(
        reactor,
        options['auth-host'], options['auth-port'],
        options['client-key'].path, options['client-cert'].path)
    checker = PantheonHTTPChecker(
        reactor,
        options['auth-host'], options['auth-port'],
        options['client-key'].path, options['client-cert'].path)
    factory.portal = Portal(realm, [checker])

    service = MultiService()
    for endpoint in options["listen"]:
        child = StreamServerEndpointService(endpoint, factory)
        child.setServiceParent(service)
    return service
