#!/usr/bin/env python
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io

from setuptools import find_packages
from setuptools import setup

# Configure the required packages and scripts to install, depending on
# Python version and OS.
DEPENDENCIES = [
    'httplib2>=0.9.1',
    'oauth2client>=2.1.0',
    'setuptools>=18.5',
    'six>=1.9.0',
    'fasteners>=0.14.1'
]

CONSOLE_SCRIPTS = [
    'oauth2l = oauth2l:main',
]

with io.open('README.md', 'r') as fh:
    README = fh.read()

setup(
    name='google-oauth2l',
    version='1.0.1',
    description='command-line google oauth tools',
    long_description=README,
    url='http://github.com/google/oauth2l',
    author='Craig Citro',
    author_email='craigcitro@google.com',
    # Contained modules and scripts.
    packages=find_packages(),
    entry_points={'console_scripts': CONSOLE_SCRIPTS},
    install_requires=DEPENDENCIES,
    # PyPI package information.
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    license='Apache 2.0',
    keywords='apitools',
)
