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
import emailprotectionslib.dmarc as dmarc
import email
import email.utils
import re


class NoRecordError(Exception):
	pass


class Dmarc(object):
	
	def __init__(self, message = None, dmarc_string_func=None):
		if message:
			self.msg = email.message_from_string(message)
		else:
			self.msg = ''
		self.raw_msg = message
		self.dmarc_obj = dmarc.DmarcRecord()
		self.RFC_FROM_DOMAIN = email.utils.parseaddr(self.msg['From'])[1].split('@',1)[1]
		if dmarc_string_func is None:
			self.dmarc_string = dmarc.get_dmarc_string_for_domain(self.RFC_FROM_DOMAIN)
		else:
			self.dmarc_string = dmarc_string_func(self.RFC_FROM_DOMAIN)
		(self.dmarc_obj).process_tags(self.dmarc_string)
		

	def get_dmarc_record(self):
		try:
			dmarc_record = (self.dmarc_obj).from_domain(self.RFC_FROM_DOMAIN)
			if dmarc_record is None:
				raise NoRecordError('No dmarc record was found for the domain')
		except NoRecordError as e:
		 	print('NoRecordError encountered')
		else:
			return dmarc_record

	def get_dkim_alignment_policy(self):
		return (self.dmarc_obj).dkim_alignment

	def get_spf_alignment_policy(self):
		return (self.dmarc_obj).spf_alignment

	def dmarc_verify_dkim_alignment(self ,message, raw_message):
		headers, body = dkim.rfc822_parse(self.raw_msg)
		sigheaders = [(x,y) for x,y in headers if x.lower() == b"dkim-signature"]
		sig = dkim.parse_tag_value(sigheaders[0][1])
		d_equal_domain = sig[b'd']
		from_domain = self.msg['From']
		# Use the 'adkim' alignment value
		if self.dmarc_obj.dkim_alignment is 's':
			if d_equal_domain == self.RFC_FROM_DOMAIN:
				res = 'pass'
			else:
				res = 'fail'
		else:
			if d_equal_domain.decode('utf-8') in self.RFC_FROM_DOMAIN:
				res = 'pass'
			else:
				res = 'fail'
		return res

	def dmarc_verify_spf_alignment(self ,message):
		regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
	                    "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
	                    "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
		start = self.msg['Authentication-Results'].find('smtp.mailfrom=')
		spf_verified_domain = None
		for domain in re.findall(regex, self.msg['Authentication-Results'][start+14:]):
			spf_verified_domain = domain[0]
		spf_verified_domain.split('@',1)[1]
		# Use the 'aspf' alignment value
		if self.dmarc_obj.spf_alignment is 's':
			if spf_verified_domain == self.RFC_FROM_DOMAIN:
				res = 'pass'
			else:
				res = 'fail'
		else:
			if spf_verified_domain in self.RFC_FROM_DOMAIN:
				res = 'pass'
			else:
				res = 'fail'
		return res
