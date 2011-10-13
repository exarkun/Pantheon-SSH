
from twisted.web.client import Agent

from pantheonssh._httpclient import StringProducer, readBody

class BadResponse(Exception):
    def __init__(self, response):
        self.response = response


    def __repr__(self):
        return '<BadResponse code=%d>' % (self.response.code,)



class APIClientMixin(object):
    """
    @ivar _host: The hostname or dotted-quad IPv4 address of the HTTP server
        against which to authenticate.

    @ivar _port: The port number of the HTTP server against which to
        authenticate.

    @ivar _reactor: An L{IReactorSSL} provider to use to issue HTTP requests.
    """

    def __init__(self, reactor, host, port):
        self._reactor = reactor
        self._host = host
        self._port = port


    def _request(self, method, url, headers, body=None):
        agent = Agent(self._reactor)
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


    def _getURL(self, site, method):
        # XXX Add some direct unit tests for this - including proper quoting of
        # the site identifier
        return 'http://%s:%d/sites/%s/%s' % (
            self._host, self._port, site, method)


