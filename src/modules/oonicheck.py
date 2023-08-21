#!/usr/bin/env python3
import os
import csv
import sys
import re
import errno
import logging
from datetime import datetime
import urllib.request

from urllib.parse import urlparse

import stem.descriptor.server_descriptor as descriptor

import util

log = logging.getLogger(__name__)


target_urls = [
    "https://ooni.org/robots.txt",
    "https://www.google.com/robots.txt",
    "https://www.apple.com/robots.txt",
    "https://www.bbc.com/robots.txt",
    "https://www.facebook.com/robots.txt",
    "https://twitter.com/robots.txt"
]

target_urls = [
    "https://ooni.org/robots.txt"
]

# Targets are formatted as destinations_list, target
targets = [
    ([(urlparse(t).netloc, 443)], t) for t in target_urls
]

def fetch_page(exit_desc, target, wr):
    exit_url = util.exiturl(exit_desc.fingerprint)
    print(f"Probing exit relay {exit_url} for {target}.")

    ts = datetime.utcnow()
    try:
        urllib.request.urlopen(target, timeout=10).read().decode("utf-8")
        wr.writerow((target, exit_desc.fingerprint, exit_desc.address, ts, "ok", ""))
    except Exception as err:
        log.warning("urllib.request.urlopen for %s says: %s." %
                    (exit_desc.fingerprint, err))
        wr.writerow((target, exit_desc.fingerprint, exit_desc.address, ts, "fail", str(err)))

def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, target, **kwargs):
    try:
        os.makedirs("ooniscan")
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise

    with open(os.path.join("ooniscan",
                           exit_desc.fingerprint + ".csv"), "a+") as f:
        wr = csv.writer(f, quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
        run_python_over_tor(fetch_page, exit_desc, target, wr)
