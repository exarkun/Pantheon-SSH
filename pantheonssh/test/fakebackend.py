
import json

from OpenSSL.SSL import (
    TLSv1_METHOD, VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT, FILETYPE_PEM,
    Context)

from twisted.internet import reactor
from twisted.internet.ssl import KeyPair, PrivateCertificate, DN
from twisted.python.filepath import FilePath
from twisted.application.service import Service
from twisted.web.http import NOT_FOUND
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.conch.ssh.keys import Key


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

    def __init__(self, sites, authorizations, passwords, keys):
        Resource.__init__(self)
        self.sites = sites
        self.authorizations = authorizations
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
        if request.postpath[0] == 'sites':
            if request.postpath[1] in self.sites:
                if request.postpath[2] == 'get-authorization':
                    return json.dumps(self.authorizations[request.postpath[1]])
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



class _StubContextFactory(object):
    def __init__(self, context):
        self._context = context


    def getContext(self):
        return self._context



class MockPantheonAuthServer(Service):
    """
    A web service which simulates the Pantheon authentication and authorization
    HTTPS REST API.  See L{MockPantheonAuthResource} for details.

    @ivar reactor: The reactor to use to set up the HTTPS server.

    @ivar resource: The root of the mock server's resource hierarchy.

    @ivar ca: A CA certificate to use to generate a certificate for the HTTPS
        server.  This is also the certificate which will be expected and
        required to have signed the client's certificate.
    @type ca: L{twisted.internet.ssl.PrivateCertificate}
    """
    def __init__(self, reactor, resource, ca):
        self.reactor = reactor
        self.resource = resource
        self.ca = ca


    def getServerContext(self):
        """
        Generate a new L{OpenSSL.SSL.Context} object configured to use a
        certificate signed by C{self.ca} and only accept connections from peers
        which are also using a certificate signed by C{self.ca}.
        """
        # Generate a new key for the server and have the CA sign a certificate
        # for it.
        key = KeyPair.generate(size=512)
        req = key.certificateRequest(DN(commonName='localhost'))
        certData = self.ca.signCertificateRequest(req, lambda dn: True, 1)
        cert = PrivateCertificate.load(certData, key)

        # Use the new key/certificate
        context = Context(TLSv1_METHOD)
        context.use_privatekey(key.original)
        context.use_certificate(cert.original)
        context.check_privatekey()

        # Allow peer certificates signed by the CA
        store = context.get_cert_store()
        store.add_cert(self.ca.original)

        # Verify the peer certificate and require that they have one.
        def verify(conn, cert, errno, depth, preverify_ok):
            return preverify_ok
        context.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT, verify)
        return context


    def startService(self):
        Service.startService(self)
        self.factory = Site(self.resource)
        contextFactory = _StubContextFactory(self.getServerContext())
        self.port = self.reactor.listenSSL(0, self.factory, contextFactory)


    def stopService(self):
        Service.stopService(self)
        return self.port.stopListening()



class FakeBackendMixin(object):
    def setUp(self):
        """
        Create a L{PantheonHTTPChecker} pointed at a mock authentication service
        with some simple site and user information.
        """
        self.site = 'example.com'
        self.cwd = '/some/path'
        self.uid = 1542
        self.username = 'alice'
        self.password = 'correct password'
        keyString = FilePath(__file__).sibling('id_rsa').getContent()
        self.privateKey = Key.fromString(keyString)

        caKeyString = FilePath(__file__).sibling('cakey.pem').getContent()
        self.caKey = KeyPair.load(caKeyString, FILETYPE_PEM)
        caCertString = FilePath(__file__).sibling('cacert.pem').getContent()
        self.caCert = PrivateCertificate.load(
            caCertString, self.caKey, FILETYPE_PEM)

        self.resource = MockPantheonAuthResource(
            sites={self.site: [self.username]},
            authorizations={self.site: dict(cwd=self.cwd, uid=self.uid)},
            passwords={self.username: self.password},
            keys={self.username: self.privateKey},
            )
        self.server = MockPantheonAuthServer(
            reactor, self.resource, self.caCert)
        self.server.startService()
        self.addCleanup(self.server.stopService)
