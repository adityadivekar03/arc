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

from dkim.types import Signature

class AMS(object):
	def __init__(self,message=None):
		self.message = message
		self.obj = dkim.DKIM(message=message)
		self.parse_message()
		
	def parse_message(self):
		if self.message:
			self.headers, self.body = dkim.rfc822_parse(self.message)
		else:
			self.headers, self.body = [], ''

	def sign(self, selector, domain, privkey):
		sig = (self.obj).sign(selector = selector, domain = domain, privkey=privkey,sign_type=Signature.ams)
		return sig

	def verify(self, message=None, dnsfunc=None):
		if dnsfunc:
			res = (self.obj).verify(message=message,sign_type=Signature.ams, dnsfunc=dnsfunc)
		else:
			res = (self.obj).verify(message=message,sign_type=Signature.ams)
		return res
