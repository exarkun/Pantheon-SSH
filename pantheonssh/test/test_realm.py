
"""
Tests for L{pantheonssh.realm}.
"""

from errno import EPERM
from signal import SIGHUP

from zope.interface import implements
from zope.interface.verify import verifyObject, verifyClass

from twisted.python.log import addObserver, removeObserver
from twisted.internet.error import ProcessExitedAlready
from twisted.internet.interfaces import IProcessTransport, IReactorProcess
from twisted.internet.protocol import ProcessProtocol
from twisted.internet import reactor
from twisted.trial.unittest import TestCase
from twisted.cred.portal import IRealm
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh.session import SSHSession

from pantheonssh.realm import PantheonSession, PantheonSite, PantheonRealm
from pantheonssh.test.fakebackend import FakeBackendMixin
from pantheonssh.test.test_tap import SSL_KEY, SSL_CERT


class Anything(object):
    """
    An object that compares equal to all other objects.
    """
    def __eq__(self, other):
        return True



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


class MemoryProcessTransport(object):
    """
    A fake implementation of part of L{IProcessTransport} which can be signaled
    if and only if the user id matches that used to launch the process.

    @ivar signals: A C{list} to which any signal successfully sent to this fake
        process is appended.
    """
    implements(IProcessTransport)

    def __init__(self, os):
        self._os = os
        self._uid = self._os.getuid()
        self._exited = False
        self.signals = []
        self.stdinClosed = False


    def signalProcess(self, signal):
        if self._exited:
            raise ProcessExitedAlready()
        if self._os.getuid() != self._uid:
            raise OSError(EPERM)
        self.signals.append(signal)


    def closeStdin(self):
        self.stdinClosed = True


    def closeChildFD(self, fd):
        if fd == 0:
            self.stdinClosed = True

    # Stub implementations of the rest; these are unused for now, so they can be
    # empty.  However, they are required for verifyClass to succeed, which we
    # want to be possible to at least tell us that the above implemented methods
    # have the right signatures.
    def closeStdout(self):
        pass


    def closeStderr(self):
        pass


    def write(self, bytes):
        pass


    def writeSequence(self, seq):
        pass


    def writeToChild(self, fd, bytes):
        pass


    def getHost(self):
        pass


    def getPeer(self):
        pass


    def loseConnection(self):
        pass


# Ensure that the signatures match
verifyClass(IProcessTransport, MemoryProcessTransport)


class MemoryProcessReactor(object):
    """
    A fake implementation of L{IReactorProcess} which merely records the
    parameters of C{spawnProcess} calls.
    """
    implements(IReactorProcess)

    def __init__(self, os):
        self._os = os
        self.processes = []


    def spawnProcess(self, processProtocol, executable, args=(), env={},
                     path=None, uid=None, gid=None, usePTY=0, childFDs=None):
        if self._os.geteuid() != 0:
            raise OSError(EPERM)
        self.processes.append((
                processProtocol, executable, args, env,
                path, uid, gid, usePTY, childFDs))
        return MemoryProcessTransport(self._os)


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
        cwd = "/some/path"
        expectedUID = 58927

        site = PantheonSite(None, cwd, expectedUID)
        messages = []
        site.logExecCommand = messages.append

        nobody = 99
        mockos = MockProcessState(0, 0)
        mockos.setegid(nobody)
        mockos.seteuid(nobody)
        proc = MemoryProcessReactor(mockos)
        session = PantheonSession(site)
        session.reactor = proc
        session.os = mockos
        expectedProto = object()
        session.execCommand(expectedProto, "echo 'hello, world'")
        self.assertIsInstance(session._process, MemoryProcessTransport)
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

        # Ensure the command is logged
        self.assertEqual(["echo 'hello, world'"], messages)


    def test_windowChanged(self):
        """
        L{PantheonSession} disregards window change notifications.
        """
        session = PantheonSession(None)
        session.windowChanged((2, 3, 4, 5))


    def test_eofReceived(self):
        """
        When the eof event is received, L{PantheonSession} closed the standard
        input of its child process.
        """
        mockos = MockProcessState(0, 0)
        session = PantheonSession(None)
        process = session._process = MemoryProcessTransport(mockos)
        session.eofReceived()
        self.assertTrue(process.stdinClosed)


    def test_closed(self):
        """
        When the closed event is received, L{PantheonSession} closed the
        standard input of its child process and signals it with C{SIGHUP}.
        """
        mockos = MockProcessState(0, 0)
        mockos.seteuid(100)
        session = PantheonSession(None)
        session.os = mockos
        process = session._process = MemoryProcessTransport(mockos)
        session.closed()
        self.assertTrue(process.stdinClosed)
        self.assertEqual(process.signals, [SIGHUP])
        self.assertEqual(mockos.geteuid(), 100)


    def test_alreadyExited(self):
        """
        No unhandled exceptions are raised if the channel receives eof or is
        closed after the child process has already exited.  stdin is still
        closed and the process's euid is still set back to its original value.
        """
        mockos = MockProcessState(0, 0)
        mockos.seteuid(100)
        session = PantheonSession(None)
        session.os = mockos
        process = session._process = MemoryProcessTransport(mockos)
        process._exited = True
        session.closed()
        self.assertTrue(process.stdinClosed)
        self.assertEqual(mockos.geteuid(), 100)



class PantheonSiteTests(TestCase):
    """
    Tests for L{PantheonSite} which represents an SSH client and allows it to
    execute certain commands on the system.
    """
    def test_interface(self):
        """
        A L{PantheonSite} instance provides L{IConchUser}.
        """
        self.assertTrue(
            verifyObject(IConchUser, PantheonSite(None, None, None)))


    def test_sessionChannel(self):
        """
        L{PantheonSite.lookupChannel} returns a L{SSHSession} when the
        I{session} channel is requested.
        """
        cwd = "/foo/bar"
        uid = 5812
        avatar = PantheonSite(None, cwd, uid)
        channel = avatar.lookupChannel("session", 2 ** 16, 2 ** 16, "")
        self.assertIsInstance(channel, SSHSession)


    def test_sessionAdapter(self):
        """
        Adapting L{PantheonSite} to L{ISession}, as L{SSHSession} does, results
        in an instance of L{PantheonSession}.
        """
        avatar = PantheonSite(None, None, None)
        session = ISession(avatar)
        self.assertIsInstance(session, PantheonSession)
        self.assertIdentical(avatar, session._site)


    def test_logExecCommand(self):
        """
        L{PantheonSite.logExecCommand} emits a log event identifying the site it
        represents and a command which was executed on behalf of that site.
        """
        siteId = "example.com"
        cwd = "/random/path"
        uid = 1234
        command = "upload the files"
        avatar = PantheonSite(siteId, cwd, uid)

        messages = []
        addObserver(messages.append)
        self.addCleanup(removeObserver, messages.append)

        avatar.logExecCommand(command)
        self.assertEqual(
            [dict(event='execCommand', siteId=siteId,
                  cwd=cwd, uid=uid, command=command,
                  isError=False, message=(), system='-',
                  time=Anything())],
            messages)


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
            reactor, '127.0.0.1', self.server.port.getHost().port,
            SSL_KEY.path, SSL_CERT.path)


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
        def cbAvatar((interface, avatar, logout)):
            self.assertIdentical(IConchUser, interface)
            self.assertIsInstance(avatar, PantheonSite)
            self.assertEqual(self.cwd, avatar.cwd)
            self.assertEqual(self.uid, avatar.uid)
        d.addCallback(cbAvatar)
        return d
