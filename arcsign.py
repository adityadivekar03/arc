#!/usr/bin/env python

# Copyright (c) 2016 Aditya Divekar <adityadivekar03@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""General script to get a message ARC signed from the terminal."""

import sys

from arc_authentication_results import aar
from arc_message_signature import ams_sign
from arc_seal import arc_seal_sign

if len(sys.argv) < 4 or len(sys.argv) > 5:
    print("Usage: arcsign.py selector domain privatekeyfile [identity]", file=sys.stderr)
    sys.exit(1)

if sys.version_info[0] >= 3:
    # Make sys.stdin and stdout binary streams.
    sys.stdin = sys.stdin.detach()
    sys.stdout = sys.stdout.detach()

selector = sys.argv[1].encode('ascii')
domain = sys.argv[2].encode('ascii')
privatekeyfile = sys.argv[3]
if len(sys.argv) > 5:
    identity = sys.argv[4].encode('ascii')
else:
    identity = None

message = sys.stdin.read()

try:
	# Get ARC Authentication Results.
    obj = aar.AAR(message)
    aar_sig = obj.create_aar()

    # Get the ARC Message Signature.
    obj = ams_sign.AMS(aar_sig + message)
    ams = obj.sign(selector, domain, privatekeyfile)

    # Get the message sealed.
    obj = arc_seal_sign.ASeal(ams + aar_sig + message)
    aseal = obj.sign(selector, domain, privatekeyfile)

    sys.stdout.write(aar_sig + ams + aseal)
    sys.stdout.write(message)
except Exception as e:
    print(e, file=sys.stderr)
    sys.stdout.write(message)
