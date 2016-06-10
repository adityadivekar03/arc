"""Testing the SPF verification module"""
import os
import unittest

from arc_authentication_results import verify_spf

class TestSPF(unittest.TestCase):
	"""Test SPF"""

	def setUp(self):
		pass

	def get_file(self, filename):
		script_dir = os.path.dirname(__file__)
		rel_path = "test_data/" + filename
		abs_path = os.path.join(script_dir, rel_path)
		self.msg = open(abs_path).read()

	def test_bad_mail_spf(self):
		self.get_file('temp4.message')
		res = verify_spf.spfverify(self.msg)
		self.assertEqual(res, 'fail')

	def test_good_mail_spf(self):
		self.get_file('temp5.message')
		res = verify_spf.spfverify(self.msg)
		self.assertTrue(res, 'pass')