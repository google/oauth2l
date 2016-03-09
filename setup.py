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

"""Setup configuration."""

import platform

try:
    import setuptools
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    import setuptools

# Configure the required packages and scripts to install, depending on
# Python version and OS.
REQUIRED_PACKAGES = [
    'google-apitools>=0.5.0',
    'oauth2client>=1.5.2',
    'setuptools>=18.5',
    'six>=1.9.0',
    ]

TESTING_PACKAGES = [
    'mock>=1.0.1',
]

CONSOLE_SCRIPTS = [
    'oauth2l = oauth2l:main',
]

py_version = platform.python_version()

if py_version < '2.7':
    raise ValueError('oauth2l requires Python 2.7 or 3.4+')

_OAUTH2L_VERSION = '0.8.0'

with open('README.md') as fileobj:
    README = fileobj.read()

setuptools.setup(
    name='google-oauth2l',
    version=_OAUTH2L_VERSION,
    description='command-line google oauth tools',
    long_description=README,
    url='http://github.com/google/oauth2l',
    author='Craig Citro',
    author_email='craigcitro@google.com',
    # Contained modules and scripts.
    packages=setuptools.find_packages(),
    entry_points={'console_scripts': CONSOLE_SCRIPTS},
    install_requires=REQUIRED_PACKAGES,
    tests_require=REQUIRED_PACKAGES + TESTING_PACKAGES,
    extras_require={
        'testing': TESTING_PACKAGES,
        },
    # PyPI package information.
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    license='Apache 2.0',
    keywords='apitools',
)
