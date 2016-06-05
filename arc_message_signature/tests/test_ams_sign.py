"""Testing the ARC Message Signature Header"""
import dkim
import os
import unittest

from arc_message_signature import ams_sign
from dkim.types import Signature

# SHOULD = (
# 	b'from', b'sender', b'reply-to', b'subject', b'date', b'message-id', b'to', b'cc',
# 	b'mime-version', b'content-type', b'content-transfer-encoding',
# 	b'content-id', b'content- description', b'resent-date', b'resent-from',
# 	b'resent-sender', b'resent-to', b'resent-cc', b'resent-message-id',
# 	b'in-reply-to', 'references', b'list-id', b'list-help', b'list-unsubscribe',
# 	b'list-subscribe', b'list-post', b'list-owner', b'list-archive', b'arc-authentication-results',
# 	b'dkim-signature')

class TestAMS(unittest.TestCase):
	"""Test AMS"""
	
	def setUp(self):
		self.msg = self.get_file('test.message')
		self.key = self.get_file('test.private')
		self.obj = ams_sign.AMS(self.msg)

	def get_file(self, filename):
		script_dir = os.path.dirname(__file__)
		rel_path = "test_data/" + filename
		abs_path = os.path.join(script_dir, rel_path)
		return open(abs_path).read()

	def dnsfunc(self, domain):
		sample_dns =  """\
	k=rsa; \
	p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANmBe10IgY+u7h3enWTukkqtUD5PR52T\
	b/mPfjC0QJTocVBq6Za/PlzfV+Py92VaCak19F4WrbVTK5Gg5tW220MCAwEAAQ=="""

		_dns_responses = {
	          'example._domainkey.canonical.com.': sample_dns,
	          'test._domainkey.example.com.': self.get_file('test.txt'),
	          '20120113._domainkey.gmail.com.': """k=rsa; \
	p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Kd87/UeJjenpabgbFwh\
	+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQ\
	s8g3FgD2Ap3ZB5DekAo5wMmk4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbb\
	hzY8i+RQ9DpSVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5Oct\
	MEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZK9vlfuac0598H\
	Y+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21MycBX5jYchHjPY/wIDAQAB"""
	        }
		try:
		    domain = domain.decode('ascii')
		except UnicodeDecodeError:
		    return None
		return _dns_responses[domain]

	def test_sign_and_verify(self):
		obj = ams_sign.AMS(self.msg)
		sig = obj.sign(selector = b"test", domain = b"example.com", privkey=self.key)
		res = obj.verify(message = sig+self.msg, dnsfunc = self.dnsfunc)
		self.assertTrue(res)

	def test_break_bodyhash(self):
		# Using `ams_sign.verify(..)` doesn't throw the exception..why?
		obj = ams_sign.AMS(self.msg)
		sig = obj.sign(selector = b"test", domain = b"example.com", privkey=self.key)
		# Add foreign character to body to break bodyhash
		with self.assertRaises(dkim.ValidationError):
			obj.verify(message = sig+self.msg+"b", dnsfunc = self.dnsfunc)

	def test_instance_one(self):
		# A message having AAR prepended to it.
		msg = self.get_file('test2.message')
		key = self.get_file('test.private')
		obj = ams_sign.AMS(msg)
		sig = obj.sign(selector = b"test", domain = b"example.com", privkey=key)
		res = obj.verify(message = sig+msg, dnsfunc = self.dnsfunc)
		self.assertTrue(res)
		self.headers, self.body = dkim.rfc822_parse(sig+msg)
		self.sigheaders = [(x,y) for x,y in self.headers if x.lower() == b"arc-message-signature"]
		tag_val = dkim.util.parse_tag_value(self.sigheaders[0][1])
		self.assertEquals(tag_val[b'i'], '1')

	def test_adding_unsigned_header_still_verifies(self):
		obj = ams_sign.AMS(self.msg)
		sig = obj.sign(selector = b"test", domain = b"example.com", privkey=self.key)
		h, b = self.msg.split(b'\n\n', 1)
		h1 = h + b'\r\n'+b'Foo: Bar'
		msg = b'\n\n'.join((h1,b))
		res = obj.verify(message = sig+msg, dnsfunc = self.dnsfunc)
		self.assertTrue(res)

	def test_adding_signed_header_breaks_sign(self):
		obj = ams_sign.AMS(self.msg)
		sig = obj.sign(selector = b"test", domain = b"example.com", privkey=self.key)
		h, b = self.msg.split(b'\n\n', 1)
		h1 = h + b'\r\n'+b'From: Foo'
		msg = b'\n\n'.join((h1,b))
		res = obj.verify(message = sig+msg, dnsfunc = self.dnsfunc)
		self.assertFalse(res)

	def test_validate_signature_fields(self):
		obj = ams_sign.AMS(self.msg)
		#Test missing mandatory field raises error.
		sig = {b'a': b'rsa-sha256',
		b'b': b'K/UUOt8lCtgjp3kSTogqBm9lY1Yax/NwZ+bKm39/WKzo5KYe3L/6RoIA/0oiDX4kO\n \t Qut49HCV6ZUe6dY9V5qWBwLanRs1sCnObaOGMpFfs8tU4TWpDSVXaNZAqn15XVW0WH\n \t EzOzUfVuatpa1kF4voIgSbmZHR1vN3WpRtcTBe/I=',
		b'bh': b'n0HUwGCP28PkesXBPH82Kboy8LhNFWU9zUISIpAez7M=',
		b'd': b'kitterman.com',
		b'h': b'From:To:Subject:Date:Cc:MIME-Version:Content-Type:\n \t Content-Transfer-Encoding:Message-Id',
		b's': b'2016-05',
		b't': b'1299525798'}
		with self.assertRaises(dkim.ValidationError) as ve:
			dkim.validate_signature_fields(sig, sign_type=Signature.ams)
		self.assertEquals('signature missing i=', str(ve.exception))
