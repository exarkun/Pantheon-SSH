# -*- test-case-name: pantheonssh.test.test_apiclient -*-

"""
Common code for talking to the authentication backend.
"""

from urllib import quote

from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.web.client import Agent

from pantheonssh._httpclient import StringProducer, readBody

class BadResponse(Exception):
    def __init__(self, response):
        self.response = response


    def __repr__(self):
        return '<BadResponse code=%d>' % (self.response.code,)



class WebContextFactory(DefaultOpenSSLContextFactory):
    def getContext(self, host, port):
        return DefaultOpenSSLContextFactory.getContext(self)



class APIClientMixin(object):
    """
    Mixin defining methods for querying the authentication server.

    @ivar _reactor: An L{IReactorSSL} provider to use to issue HTTPS requests.

    @ivar _host: The hostname or dotted-quad IPv4 address of the HTTPS server
        against which to authenticate.

    @ivar _port: The port number of the HTTPS server against which to
        authenticate.

    @ivar _keyFile: A C{str} giving the path to a private key to use to make
        HTTPS requests.

    @ivar _certFile: A C{str} giving the path to a certificate to use to make
        HTTPS requests.
    """

    def __init__(self, reactor, host, port, keyFile, certFile):
        self._reactor = reactor
        self._host = host
        self._port = port
        self._keyFile = keyFile
        self._certFile = certFile


    def _request(self, method, url, headers, body=None):
        contextFactory = WebContextFactory(self._keyFile, self._certFile)
        agent = Agent(self._reactor, contextFactory)
        if body is not None:
            body = StringProducer(body)
        response = agent.request(method, url, headers, body)
        def cbResponse(response):
            # XXX Is this is right check to verify the server is giving us a
            # good response?
            if response.code == 200:
                return readBody(response)
            raise BadResponse(response)
        body = response.addCallback(cbResponse)
        return body


    def _getURL(self, site, operation):
        """
        Construct a URL to which a request may be issued to perform the
        specified operation on the specified site.

        @param site: A C{str} naming the site to operate on.

        @param operation: A C{str} naming the operation to perform, such as
            C{"check-key"}.

        @return: A C{str} giving the requested URL.
        """
        return 'https://%s:%d/sites/%s/%s' % (
            self._host, self._port, quote(site, ''), quote(operation, ''))


