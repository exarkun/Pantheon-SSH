# -*- test-case-name: pantheonssh.test.test_tap -*-

"""
Definition of twistd plugins for the Pantheon SSH server.
"""

from twisted.application.service import ServiceMaker

__all__ = ['pantheonssh']

pantheonssh = ServiceMaker(
    "pantheon-ssh", "pantheonssh.tap",
    "Pantheon SSH server for accepting and dispatching Drush commands",
    "pantheon-ssh")
