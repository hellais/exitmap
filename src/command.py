# Copyright 2013-2020 Philipp Winter <phw@nymity.ch>
# Copyright 2021 The Tor Project, Inc.
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Provides and API to execute system commands over torsocks.
"""

import os
import socket
import threading
import subprocess
import tempfile
import pprint
import logging

import util

log = logging.getLogger(__name__)


class Command(object):

    """
    Provide an abstraction for a shell command which is to be run.
    """

    def __init__(self, queue, circ_id, socks_port):

        self.process = None
        self.stdout = None
        self.stderr = None
        self.output_callback = None
        self.queue = queue
        self.circ_id = circ_id
        self.socks_port = socks_port

    def invoke_process(self, command):
        """
        Run the command and wait for it to finish.

        If a callback was specified, it is called with the process' output as
        argument and with a function which can be used to kill the process.
        """

        # Start process and redirect its stderr to stdout.  That makes it more
        # convenient for us to parse the output.

        self.process = subprocess.Popen(
            command,
            env=os.environ,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        if self.output_callback:

            # Read the process' output line by line and pass it to the module's
            # callback function.

            keep_reading = True
            while keep_reading:

                line = self.process.stdout.readline()
                if not line:
                    break
                else:
                    line = line.strip()

                # Look for torsocks' source port before we pass the line on
                # to the module.

                pattern = "Connection on fd [0-9]+ originating " \
                          "from [^:]+:([0-9]{1,5})"
                port = util.extract_pattern(line, pattern)

                if port:
                    self.queue.put([self.circ_id, ("127.0.0.1", int(port))])

                keep_reading = self.output_callback(line, self.process.kill)

        # Wait for the process to finish.

        self.stdout, self.stderr = self.process.communicate()

    def execute(self, command, timeout=10, output_callback=None):
        """
        Run a shell command in a dedicated process.
        """

        command = ["torsocks"] + command
        self.output_callback = output_callback

        # We run the given command in a separate thread.  The main thread will
        # kill the process if it does not finish before the given timeout.

        with tempfile.NamedTemporaryFile(prefix="torsocks_") as fd:

            log.debug("Created temporary torsocks config file %s" % fd.name)
            os.environ["TORSOCKS_CONF_FILE"] = fd.name
            os.environ["TORSOCKS_LOG_LEVEL"] = "5"

            fd.write("TorPort %d\n" % self.socks_port)
            fd.write("TorAddress 127.0.0.1\n")
            fd.flush()

            log.debug("Invoking \"%s\" in environment:\n%s" %
                      (" ".join(command), pprint.pformat(dict(os.environ))))

            thread = threading.Thread(target=self.invoke_process,
                                      args=(command,))
            thread.daemon = True
            thread.start()
            thread.join(timeout)

        # Attempt to kill the process if it did not finish in time.

        if thread.is_alive():
            log.debug("Killing process after %d seconds." % timeout)
            self.process.kill()
            thread.join()

        return self.stdout, self.stderr


# Alias class name to provide more intuitive interface.
new = Command
