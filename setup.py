#!/usr/bin/env python

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


import os
from setuptools import setup, find_packages

version = "0.1"

os.system('pip install https://gitlab.com/adityadivekar/sign-message/repository/archive.zip?ref=master')

setup(
	name = "ARC",
	version = version,
	url = "https://gitlab.com/adityadivekar/arc",
	scripts = ["arcsign.py"],
	packages = find_packages(),
	incude_packages_data = True,
	install_requires = [
		'setuptools',
		'pyspf',
		'emailprotectionslib==0.4',
		'pytest',
		'enum34',
		'py3dns',
		'ipaddress',
		'dnslib',
		'dnspython',
	],
)
