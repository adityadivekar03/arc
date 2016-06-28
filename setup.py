#!/usr/bin/env python

import os
from setuptools import setup, find_packages

version = "0.1"

os.system('pip install https://gitlab.com/adityadivekar/sign-message/repository/archive.zip?ref=master')

setup(
	name = "ARC",
	version = version,
	url = "https://gitlab.com/adityadivekar/arc",
	scripts = ["arcsign.py"],
	incude_packages_data = True,
	install_requires = [
		'setuptools',
		'pyspf',
		'emailprotectionslib==0.4',
		'pytest',
		'enum',
		'pydns',
		'ipaddr',
		'dnslib',
		'dnspython',
	],
)
