
"""
Tests for L{pantheonssh.realm}.
"""

from errno import EPERM

from zope.interface import implements
from zope.interface.verify import verifyObject, verifyClass

from twisted.internet.interfaces import IReactorProcess
from twisted.internet.protocol import ProcessProtocol
from twisted.internet import reactor
from twisted.trial.unittest import TestCase
from twisted.cred.portal import IRealm
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh.session import SSHSession

from pantheonssh.realm import PantheonSession, PantheonSite, PantheonRealm
from pantheonssh.test.fakebackend import FakeBackendMixin


class MockProcessState(object):
    """
    A fake implementation of POSIX process-global state; in particular, real and
    effective user and group id setting, which are twiddled when launching a
    process with different values for those states.

    This tries to present an interface similar to that of the C{os} module,
    since that's where many process state manipulation functions are exposed.
    """
    def __init__(self, uid, gid):
        self._realUID = self._effectiveUID = self._savedSetUID = uid
        self._realGID = self._effectiveGID = self._savedSetGID = uid


    def getuid(self):
        """
        getuid() returns the real user ID of the calling process.
        """
        return self._realUID


    def setuid(self, uid):
        """
        setuid() sets the effective user ID of the calling process.  If the
        effective UID of the caller is root, the real UID and saved set-user-ID
        are also set.
        """
        if self._effectiveUID == 0:
            self._realUID = self._effectiveGID = self._savedSetGID = uid
        else:
            raise OSError(EPERM)


    def getgid(self):
        """
        getgid() returns the real group ID of the calling process.
        """
        return self._realGID


    def setgid(self, gid):
        """
        setgid() sets the effective group ID of the calling process.  If the
        caller is the superuser, the real GID and saved set-group-ID are also
        set.
        """
        if self._effectiveUID == 0:
            self._realGID = self._effectiveGID = self._savedSetGID = gid
        else:
            raise OSError(EPERM)


    def geteuid(self):
        """
        geteuid() returns the effective user ID of the calling process.
        """
        return self._effectiveUID


    def seteuid(self, euid):
        """
        seteuid() sets the effective user ID of the calling process.
        Unprivileged user processes may only set the effective user ID to the
        real user ID, the effective user ID or the saved set-user-ID.
        """
        if self._effectiveUID == 0 or euid in (
            self._realUID, self._effectiveUID, self._savedSetUID):
            self._effectiveUID = euid
        else:
            raise OSError(EPERM)


    def getegid(self):
        """
        getegid() returns the effective group ID of the calling process.
        """
        return self._effectiveGID


    def setegid(self, egid):
        """
        seteuid() sets the effective user ID of the calling process.
        Unprivileged user processes may only set the effective user ID to the
        real user ID, the effective user ID or the saved set-user-ID.
        """
        if self._effectiveUID == 0 or egid in (
            self._realGID, self._effectiveGID, self._savedSetGID):
            self._effectiveGID = egid
        else:
            raise OSError(EPERM)



class MemoryProcessReactor(object):
    """
    A fake implementation of L{IReactorProcess} which merely records the
    parameters of C{spawnProcess} calls.
    """
    implements(IReactorProcess)

    def __init__(self, os):
        self.os = os
        self.processes = []


    def spawnProcess(self, processProtocol, executable, args=(), env={},
                     path=None, uid=None, gid=None, usePTY=0, childFDs=None):
        if self.os.geteuid() != 0:
            raise OSError(EPERM)
        self.processes.append((
                processProtocol, executable, args, env,
                path, uid, gid, usePTY, childFDs))


# Ensure that the signatures match
verifyClass(IReactorProcess, MemoryProcessReactor)


class PantheonSessionTests(TestCase):
    """
    Tests for L{PantheonSession} which implements session operations for an SSH
    connection, and which is therefore responsible for launching child processes
    requested by the SSH client.
    """
    def test_interface(self):
        """
        An L{PantheonSession} instance provides L{ISession}.
        """
        self.assertTrue(verifyObject(ISession, PantheonSession(None)))


    def test_getPty(self):
        """
        L{PantheonSession} does not allow PTYs to be allocated.
        """
        session = PantheonSession(None)
        self.assertRaises(Exception, session.getPty, "xterm", (1, 2, 3, 4), [])


    def test_openShell(self):
        """
        L{PantheonSession} does not allow a shell to be opened.
        """
        session = PantheonSession(None)
        self.assertRaises(Exception, session.openShell, ProcessProtocol())


    def test_execCommand(self):
        """
        L{PantheonSession.execCommand} launches the command as a child process,
        running it with the working directory and uid its avatar, the
        L{PantheonSite}, specifies.
        """
        nobody = 99
        cwd = "/some/path"
        expectedUID = 58927
        mockos = MockProcessState(0, 0)
        mockos.setegid(nobody)
        mockos.seteuid(nobody)
        proc = MemoryProcessReactor(mockos)
        session = PantheonSession(PantheonSite(cwd, expectedUID))
        session.reactor = proc
        session.os = mockos
        expectedProto = object()
        session.execCommand(expectedProto, "echo 'hello, world'")
        process = proc.processes.pop(0)
        proto, executable, args, env, path, uid, gid, usePTY, childFDs = process
        self.assertIdentical(expectedProto, proto)
        self.assertEqual("/bin/sh", executable)
        self.assertEqual(args, ["/bin/sh", "-c", "echo 'hello, world'"])
        # XXX What should really be in the environment?
        self.assertEqual({'HOME': cwd}, env)
        self.assertEqual(cwd, path)
        self.assertEqual(expectedUID, uid)
        # XXX What should the GID really be?
        self.assertEqual(80, gid)
        self.assertFalse(usePTY)
        self.assertIdentical(None, childFDs)

        # Ensure we end up in a good state, uid/gid-wise.
        self.assertEqual(nobody, mockos.geteuid())
        self.assertEqual(nobody, mockos.getegid())


    def test_windowChanged(self):
        """
        L{PantheonSession} disregards window change notifications.
        """
        session = PantheonSession(None)
        session.windowChanged((2, 3, 4, 5))


    def test_eofReceived(self):
        pass


    def test_closed(self):
        pass



class PantheonSiteTests(TestCase):
    """
    Tests for L{PantheonSite} which represents an SSH client and allows it to
    execute certain commands on the system.
    """
    def test_interface(self):
        """
        A L{PantheonSite} instance provides L{IConchUser}.
        """
        self.assertTrue(verifyObject(IConchUser, PantheonSite(None, None)))


    def test_sessionChannel(self):
        """
        L{PantheonSite.lookupChannel} returns a L{SSHSession} when the
        I{session} channel is requested.
        """
        cwd = "/foo/bar"
        uid = 5812
        avatar = PantheonSite(cwd, uid)
        channel = avatar.lookupChannel("session", 2 ** 16, 2 ** 16, "")
        self.assertIsInstance(channel, SSHSession)


    def test_sessionAdapter(self):
        """
        Adapting L{PantheonSite} to L{ISession}, as L{SSHSession} does, results
        in an instance of L{PantheonSession}.
        """
        avatar = PantheonSite(None, None)
        session = ISession(avatar)
        self.assertIsInstance(session, PantheonSession)
        self.assertIdentical(avatar, session._site)



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
