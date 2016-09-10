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


import dkim
import email
import re
import spf

from arc_authentication_results.verify_dmarc import Dmarc
from dkim.types import Signature


FWS = br'(?:(?:\s*\r?\n)?\s+)?'
RE_BTAG = re.compile(br'([;\s]b'+FWS+br'=)(?:'+FWS+br'[a-zA-Z0-9+/=])*(?:\r?\n\Z)?')

class AAR(object):
	def __init__(self, message = None, dmarc_string_func=None):
		self.raw_msg = message
		self.message = email.message_from_string(message)
		self.set_message(message)
		self.spf = None
		self.dkim = None
		self.dmarc = None
		self.obj = Dmarc(message=self.raw_msg, dmarc_string_func=dmarc_string_func)
		self.i = 0
		self.spf_align = None
		self.dkim_align = None

	def set_message(self, message):
		if message:
			self.headers, self.body = dkim.rfc822_parse(message)
		else:
			self.headers, self.body = [], ''

	def create_aar(self, dnsfunc=None, testing=False):
		sign_obj = dkim.DKIM(message = self.raw_msg)
		try:
			self.dkim = sign_obj.verify(dnsfunc=dnsfunc)
			if self.dkim is True:
				self.dkim = 'pass'
			else:
				self.dkim = 'none'
		except dkim.ValidationError:
			self.dkim = 'fail'

		# Check the spf and dkim alignment.
		if self.dkim == 'pass':
			self.dkim_align = (self.obj).dmarc_verify_dkim_alignment(self.message, self.raw_msg)
		
		# Since we are ignoring spf for dmarc, we only consider the dkim alignment.
		if self.dkim_align == 'pass':
			self.dmarc = 'pass'
		elif self.dkim == 'none':
			self.dmarc = 'none'
		else:
			self.dmarc = 'fail'
		
		# Get the value of the instance of the ARC Authentication Results
		sigheaders = [(x,y) for x,y in self.headers if x.lower() == b"arc-authentication-results"]
		self.i = len(sigheaders)+1
		
		# FIXME! Insert the name of the list in the AAR header.		
		sigfields = [x for x in [
			(b'i', str(self.i)),
			(b'dkim', str(self.dkim)),
			(b'dmarc', str(self.dmarc)),
        ] if x]

		sig_value = dkim.fold(b"; ".join(b"=".join(x) for x in sigfields))
		sig_value = RE_BTAG.sub(b'\\1',sig_value)
		if testing:
			aar_header = b'ARC-Authentication-Results', b' ' + sig_value
		else:
			aar_header = b'ARC-Authentication-Results:' + sig_value + b"\r\n"
		return aar_header
