# Copyright (c) 2016 Aditya Divekar
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


"""Testing ARC Authentication Results header"""
import dkim
import os
import unittest

from arc_authentication_results import aar
from arc_authentication_results.verify_dmarc import NoRecordError

class TestAAR(unittest.TestCase):
	"""Test AAR"""

	def setUp(self):
		pass

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
	          'google._domainkey.canonical.com.': sample_dns,
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

	def dmarc_string_func(self, domain):
		_dns = """v=DMARC1; p=none; rua=mailto:mailauth-reports@example.com"""
		_dns2 = """v=DMARC1; p=none; adkim=s; rua=mailto:mailauth-reports@example.com"""
		_dns3 = """v=DMARC1; p=none; adkim=r; rua=mailto:mailauth-reports@example.com"""
		_responses = {
	          'example.com': _dns,
	          'p.example.com': _dns2,
	          'f.example.com': _dns3,
	        }
		return _responses[domain]

	def test_aar_instance(self):
		# Test when no previous instance of AAR is present.
		self.msg = self.get_file('temp1.message')
		obj = aar.AAR(self.msg, self.dmarc_string_func)
		sig = obj.create_aar(self.dnsfunc, True)
		tag = dkim.parse_tag_value(sig[1])
		instance = tag[b'i']
		self.assertEqual(instance , b'1')
		# Test when previous instance of AAR is present.
		self.msg = self.get_file('temp2.message')
		obj = aar.AAR(self.msg, self.dmarc_string_func)
		sig = obj.create_aar(self.dnsfunc, True)
		tag = dkim.parse_tag_value(sig[1])
		instance = tag[b'i']
		self.assertEqual(instance , b'2')

	def test_dkim_and_dmarc_fail(self):
		# No alignment mode specified.
		self.msg = self.get_file('temp3.message')
		obj = aar.AAR(self.msg)
		sig = obj.create_aar(testing=True)
		tag = dkim.parse_tag_value(sig[1])
		dkim_res = tag[b'dkim']
		self.assertEqual(dkim_res, b'fail')
		dmarc_res = tag[b'dmarc']
		self.assertEqual(dmarc_res, b'fail')

	def test_dkim_and_dmarc_pass(self):
		# No alignment mode specified.
		self.msg = self.get_file('temp1.message')
		key = self.get_file('temp.private')
		sign = dkim.sign(self.msg, b"test", b"example.com", key)
		obj = aar.AAR(sign.decode('utf-8')+self.msg, self.dmarc_string_func)
		sig = obj.create_aar(self.dnsfunc,True)
		tag = dkim.parse_tag_value(sig[1])
		dkim_res = tag[b'dkim']
		self.assertEqual(dkim_res, b'pass')
		dmarc_res = tag[b'dmarc']
		self.assertEqual(dmarc_res, b'pass')

	def test_strict_alignment(self):
		# The d_equal_domain is 'example.com', but
		# the RFC5322.FROM domain is 'p.example.com'.
		# Hence dmarc fails due to 'strict' alignment rule.
		self.msg = self.get_file('temp6.message')
		key = self.get_file('temp.private')
		sign = dkim.sign(self.msg, b"test", b"example.com", key)
		obj = aar.AAR(sign.decode('utf-8')+self.msg, self.dmarc_string_func)
		sig = obj.create_aar(self.dnsfunc, True)
		tag = dkim.parse_tag_value(sig[1])
		dkim_res = tag[b'dkim']
		self.assertEqual(dkim_res, b'pass')
		dmarc_res = tag[b'dmarc']
		self.assertEqual(dmarc_res, b'fail')

	def test_relaxed_alignment(self):
		# The d_equal_domain is 'example.com', but
		# the RFC5322.FROM domain is 'p.example.com'.
		# Hence dmarc passes due to 'relaxed' alignment rule.
		self.msg = self.get_file('temp7.message')
		key = self.get_file('temp.private')
		sign = dkim.sign(self.msg, b"test", b"example.com", key)
		obj = aar.AAR(sign.decode('utf-8')+self.msg, self.dmarc_string_func)
		sig = obj.create_aar(self.dnsfunc, True)
		tag = dkim.parse_tag_value(sig[1])
		dkim_res = tag[b'dkim']
		self.assertEqual(dkim_res, b'pass')
		# So dmarc also fails.
		dmarc_res = tag[b'dmarc']
		self.assertEqual(dmarc_res, b'pass')
