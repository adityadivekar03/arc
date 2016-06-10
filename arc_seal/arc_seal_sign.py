import dkim
from arc_message_signature import ams_sign

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
				if not (self.obj).verify(message=self.message, idx=1, sign_type=Signature.ams,dnsfunc=dnsfunc):
					raise
			except Exception:
				cv = 'fail'
			if cv != 'fail':
				instances = len(sigheaders)
				for i in (1, instances):
					sig = dkim.util.parse_tag_value(sigheaders[i-1][1])
					if (i<instances and sig['cv']=='pass' or i==instances and sig['cv']=='none'):
						if (self.obj).verify(message=self.message,idx=i-1,sign_type=Signature.aseal,dnsfunc=dnsfunc):
							cv = 'pass'
							continue
						else:
							cv = 'fail'
							break

		# Got the `cv` status now.
		sig = self.obj.sign(selector = selector, domain = domain, privkey=privkey,sign_type=Signature.aseal,cv=cv)
		return sig
