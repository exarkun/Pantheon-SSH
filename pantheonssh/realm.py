# -*- test-case-name: pantheonssh.test.test_realm -*-

"""
This module implements a L{twisted.cred} realm and avatar which can authorize
clients to access certain commands on their site.
"""

import json
from signal import SIGHUP

from zope.interface import implements

from twisted.python.log import msg
from twisted.python.components import registerAdapter
from twisted.cred.portal import IRealm
from twisted.internet.error import ProcessExitedAlready
from twisted.web.http_headers import Headers
from twisted.conch.avatar import ConchUser
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh.session import SSHSession

from pantheonssh._apiclient import APIClientMixin


class PantheonSession(object):
    """
    L{PantheonSession} implements a session channel for a L{PantheonSite}.  It
    only allows commands to be executed, and causes them to be executed in a
    manner appropriate for that L{PantheonSite}.
    """
    implements(ISession)

    os = None
    reactor = None
    shell = "/bin/sh"

    def __init__(self, site):
        self._site = site


    def execCommand(self, proto, command):
        """
        Execute the client-specified command in the working directory and with
        the uid specified by our site object.
        """
        reactor = self.reactor
        if reactor is None:
            from twisted.internet import reactor

        os = self.os
        if os is None:
            import os

        saved = os.geteuid()
        try:
            os.seteuid(0)

            self._process = reactor.spawnProcess(
                proto,
                executable=self.shell,
                args=[self.shell, "-c", command],
                env={'HOME': self._site.cwd},
                path=self._site.cwd,
                uid=self._site.uid,
                gid=80,
                usePTY=False,
                childFDs=None)
        finally:
            os.seteuid(saved)
        self._site.logExecCommand(command)


    def getPty(self, term, windowSize, modes):
        """
        Reject all PTY requests.
        """
        raise Exception("Unsupported PTY request from client")


    def openShell(self, proto):
        """
        Reject all shell requests.
        """
        raise Exception("Unsupported shell request from client")


    def windowChanged(self, newSize):
        """
        Ignore all window size change events.
        """


    def eofReceived(self):
        """
        When the client indicates eof on the channel, indicate this to the child
        process by closing its stdin.
        """
        self._process.closeStdin()


    def closed(self):
        """
        When the channel is actually closed, try to get the child process to
        exit by closing its stdin and sending it a hang-up signal.
        """
        os = self.os
        if os is None:
            import os

        self._process.closeStdin()
        saved = os.geteuid()
        try:
            # Gain the permissions to send a signal to the process.
            # XXX Would it be better to send the signal as the UID the process
            # was spawned with?
            os.seteuid(0)
            try:
                self._process.signalProcess(SIGHUP)
            except ProcessExitedAlready:
                pass
        finally:
            os.seteuid(saved)



class PantheonSite(object, ConchUser):
    """
    L{PantheonSite} represents a user's access to a particular site on the
    system.

    @ivar siteId: A C{str} identifying this site.

    @ivar cwd: A C{str} representing the working directory in which commands are
        started.

    @ivar uid: A C{int} giving the system user id with which commands are
        launched.
    """
    conn = None

    def __init__(self, siteId, cwd, uid):
        ConchUser.__init__(self)

        # Allow the user to open a channel of type session.  This implementation
        # will look up the ISession adapter for this site and use the resulting
        # object to authorize any SSH actions.
        self.channelLookup['session'] = SSHSession

        self.siteId = siteId
        self.cwd = cwd
        self.uid = uid


    def logExecCommand(self, command):
        """
        Log a command executed for this site.
        """
        msg(event='execCommand', siteId=self.siteId,
            cwd=self.cwd, uid=self.uid, command=command)


registerAdapter(PantheonSession, PantheonSite, ISession)


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
            return (
                IConchUser,
                PantheonSite(avatarId, params['cwd'], params['uid']),
                lambda: None)
        d.addCallback(cbResponse)
        return d

