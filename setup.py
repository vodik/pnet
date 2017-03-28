#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import codecs
from setuptools import setup, find_packages


def read(fname):
    file_path = os.path.join(os.path.dirname(__file__), fname)
    return codecs.open(file_path, encoding='utf-8').read()


setup(
    name='pnet',
    version='0.0.1',
    author='Simon Gomizelj',
    author_email='simon@vodik.xyz',
    packages=find_packages(),
    license='Apache 2',
    url='https://github.com/vodik/pnet',
    description='Fast zero-copy packet creating and parsing module',
    long_description=read('README.rst'),
    classifiers=[
        'Development Status :: 4 - Beta',
	"Intended Audience :: Developers",
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License'
    ],
)
