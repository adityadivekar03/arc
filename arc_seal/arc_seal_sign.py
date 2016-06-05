import dkim

from dkim.types import Signature
from dkim.dnsplug import get_txt

class ASeal(object):
	def __init__(self, message=None):
		self.message = message
		self.obj = dkim.DKIM(message=message)
		self.set_message(message)

	def set_message(self, message):
		if message:
			self.headers, self.body = dkim.rfc822_parse(message)
		else:
			self.headers, self.body = [], ''

	def sign(self, selector, domain, privkey, dnsfunc=get_txt):
		# We need to get the `cv` status before we can sign the current instance.
		# For this we need to verify all previous ARC-Seal instances and the topmost
		# ARC-Message-Signature.
		cv = 'none'
		sigheaders = [(x,y) for x,y in self.headers if x.lower() == b"arc-seal"]
		if len(sigheaders) == 0:
			cv = 'none'
		else:
			try:
				(self.obj).verify(message=self.message, sign_type=Signature.ams,dnsfunc=dnsfunc)
			except Exception:
				cv = 'fail'
			if cv != 'fail':
				for i in (1, len(sigheaders)):
					sig = dkim.util.parse_tag_value(sigheaders[i-1][1])
					if (i>1 and sig['cv']=='pass' or i==1 and sig['cv']=='none'):
						if (self.obj).verify(message=self.message,idx=i-1,sign_type=Signature.aseal,dnsfunc=dnsfunc):
							cv = 'pass'
							continue
						else:
							cv = 'fail'
							break

		# Got the `cv` status now.
		sig = self.obj.sign(selector = selector, domain = domain, privkey=privkey,sign_type=Signature.aseal,cv=cv)
		return sig
