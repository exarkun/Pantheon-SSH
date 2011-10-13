# -*- test-case-name: pantheonssh.test.test_realm -*-

"""
This module implements a L{twisted.cred} realm and avatar which can authorize
clients to access certain commands on their site.
"""

import json

from zope.interface import implements

from twisted.cred.portal import IRealm
from twisted.web.http_headers import Headers

from pantheonssh._apiclient import APIClientMixin


class PantheonSite(object):
    """
    L{PantheonSite} represents a user's access to a particular site on the
    system.

    @ivar cwd: A C{str} representing the working directory in which commands are
        started.

    @ivar uid: A C{int} giving the system user id with which commands are
        launched.
    """
    def __init__(self, cwd, uid):
        self.cwd = cwd
        self.uid = uid



class PantheonRealm(APIClientMixin, object):
    """
    L{PantheonRealm} creates user objects which grant SSH-based access to a
    particular site on the system.
    """
    implements(IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        """
        Create a new user object for the specified site.

        @param avatarId: A C{str} giving the site for which to create a user
            object.

        @param mind: Unused

        @param *interfaces: The kind of user object to create; only
            L{IConchUser} is supported.
        """
        url = self._getURL(avatarId, 'get-authorization')
        d = self._request("GET", url, Headers())
        def cbResponse(response):
            params = json.loads(response)
            return PantheonSite(params['cwd'], params['uid'])
        d.addCallback(cbResponse)
        return d

