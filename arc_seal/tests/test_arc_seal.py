"""Testing the ARC Message Signature Header"""
import dkim
import os
import unittest

from arc_seal import arc_seal_sign


class TestASeal(unittest.TestCase):

	def setUp(self):
		self.msg = self.get_file('temp0.message')
		self.key = self.get_file('temp.private')
		self.obj = arc_seal_sign.ASeal(self.msg)

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
	          'test._domainkey.example.com.': self.get_file('temp.txt'),
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


	def test_seal_sign_and_verify(self):
		sig = (self.obj).sign(selector=b"test", domain=b"example.com", privkey=self.key, dnsfunc=self.dnsfunc)
		headers, body = dkim.rfc822_parse(sig+self.msg)
		sigheaders = [(x,y) for x,y in headers if x.lower() == b"arc-seal"]
		tag_val = dkim.util.parse_tag_value(sigheaders[0][1])
		self.assertEquals(tag_val[b'cv'], 'none')

	def test_tampered_arc_seal_breaks_chain(self):
		msg = self.get_file('temp1.message')
		obj = arc_seal_sign.ASeal(msg)
		sig = obj.sign(selector=b"test", domain=b"example.com", privkey=self.key, dnsfunc=self.dnsfunc)
		headers, body = dkim.rfc822_parse(sig+msg)
		sigheaders = [(x,y) for x,y in headers if x.lower() == b"arc-seal"]
		tag_val = dkim.util.parse_tag_value(sigheaders[0][1])
		self.assertEquals(tag_val[b'cv'], 'fail')

	def test_chain_length_two(self):
		msg = self.get_file('temp2.message')
		obj = arc_seal_sign.ASeal(msg)
		sig = obj.sign(selector=b"test", domain=b"example.com", privkey=self.key, dnsfunc=self.dnsfunc)
		headers, body = dkim.rfc822_parse(sig+msg)
		sigheaders = [(x,y) for x,y in headers if x.lower() == b"arc-seal"]
		tag_val = dkim.util.parse_tag_value(sigheaders[0][1])
		self.assertEquals(tag_val[b'cv'], 'pass')

	def test_chain_length_three(self):
		msg = self.get_file('temp3.message')
		obj = arc_seal_sign.ASeal(msg)
		sig = obj.sign(selector=b"test", domain=b"example.com", privkey=self.key, dnsfunc=self.dnsfunc)
		headers, body = dkim.rfc822_parse(sig+msg)
		sigheaders = [(x,y) for x,y in headers if x.lower() == b"arc-seal"]
		tag_val = dkim.util.parse_tag_value(sigheaders[0][1])
		self.assertEquals(tag_val[b'cv'], 'pass')

	def test_chain_length_four(self):
		msg = self.get_file('temp4.message')
		obj = arc_seal_sign.ASeal(msg)
		sig = obj.sign(selector=b"test", domain=b"example.com", privkey=self.key, dnsfunc=self.dnsfunc)
		headers, body = dkim.rfc822_parse(sig+msg)
		sigheaders = [(x,y) for x,y in headers if x.lower() == b"arc-seal"]
		tag_val = dkim.util.parse_tag_value(sigheaders[0][1])
		self.assertEquals(tag_val[b'cv'], 'pass')
