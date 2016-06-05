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
