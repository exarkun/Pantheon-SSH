# -*- test-case-name: pantheonssh.test.test_checker -*-

"""
This module implements a L{twisted.cred} checker which can authenticate clients
using passwords or SSH key pairs.
"""

import json

from zope.interface import implements

from twisted.internet.defer import succeed
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword, ISSHPrivateKey
from twisted.web.http_headers import Headers
from twisted.web.client import Agent
from twisted.conch.error import ValidPublicKey
from twisted.conch.ssh.keys import BadKeyError, Key

from pantheonssh._httpclient import StringProducer, readBody


class PantheonHTTPChecker(object):
    """
    This is a checker which validates credentials by making HTTP requests to a
    REST API which sits on top of the actual credentials data.

    @ivar _reactor: An L{IReactorSSL} provider to use to issue HTTP requests.

    @ivar _host: The hostname or dotted-quad IPv4 address of the HTTP server
        against which to authenticate.

    @ivar _port: The port number of the HTTP server against which to
        authenticate.
    """
    implements(ICredentialsChecker)

    credentialInterfaces = [IUsernamePassword, ISSHPrivateKey]

    def __init__(self, reactor, host, port):
        self._reactor = reactor
        self._host = host
        self._port = port


    def requestAvatarId(self, credentials):
        """
        Check the given credentials and return a suitable user identifier if
        they are valid.
        """
        if IUsernamePassword.providedBy(credentials):
            return self._checkPassword(credentials)
        if ISSHPrivateKey.providedBy(credentials):
            return self._checkKey(credentials)
        raise NotImplementedError()


    def _post(self, url, headers, body):
        agent = Agent(self._reactor)
        response = agent.request('POST', url, headers, body)
        def cbResponse(response):
            # XXX Is this is right check to verify the server is giving us a
            # good response?
            if response.code == 200:
                return readBody(response)
            # XXX Log this unexpected error
            raise UnauthorizedLogin()
        body = response.addCallback(cbResponse)
        return body


    def _getURL(self, site, method):
        # XXX Add some direct unit tests for this - including proper quoting of
        # the site identifier
        return 'http://%s:%d/sites/%s/%s' % (
            self._host, self._port, site, method)


    def _checkPassword(self, credentials):
        """
        Check a L{IUsernamePassword} credentials-based authentication attempt.
        Treat the username as a site identifier.  Ask the backend HTTP server if
        the password given is valid for that site.
        """
        url = self._getURL(credentials.username, 'check-password')
        body = StringProducer(json.dumps(credentials.password))
        response = self._post(url, Headers(), body)
        def cbBody(body):
            valid = json.loads(body)
            if valid:
                return credentials.username
            raise UnauthorizedLogin()
        result = response.addCallback(cbBody)
        return result


    def _blobValidForSite(self, site, blob):
        """
        Determine whether a public key blob represents a public key which may be
        used to authenticate for access to a particular site.

        @param site: A C{str} giving the name of the site to which access is
            desired.

        @param blob: A C{str} giving an SSH public key blob representing some
            public key.

        @return: A L{Deferred} which fires with C{True} if the site may be
            accessed using the key, C{False} otherwise.
        """
        # Convert from the binary format (not safe for JSON) to the OpenSSH text
        # format (an ASCII string, safe for JSON).
        try:
            publicKey = Key.fromString(blob).toString('openssh')
        except BadKeyError:
            return succeed(False)

        url = self._getURL(site, 'check-key')
        body = StringProducer(json.dumps(publicKey))
        response = self._post(url, Headers(), body)
        response.addCallback(json.loads)
        return response


    def _checkKey(self, credentials):
        """
        Check a L{ISSHPrivateKey} credentials-based authentication attempt.
        Treat the username as a site identifier.  As the backend HTTP server if
        the public key given is valid for that site.
        """
        d = self._blobValidForSite(credentials.username, credentials.blob)
        def validated(valid):
            if valid:
                if credentials.signature:
                    key = Key.fromString(credentials.blob)
                    if key.verify(credentials.signature, credentials.sigData):
                        return credentials.username
                    raise UnauthorizedLogin()
                else:
                    raise ValidPublicKey()
            else:
                raise UnauthorizedLogin()
        d.addCallback(validated)
        return d
