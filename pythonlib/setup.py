#!/usr/bin/env python

"""
setup.py file for SWIG argusWgan
"""

from distutils.core import setup, Extension


argusWgan = Extension('_argusWgan',
       extra_compile_args = ['-Wno-deprecated-declarations'], 
       sources=['argusWgan_wrap.c', 'argusWgan.c'],
       include_dirs=['../include'],
       libraries=['m','GeoIP','z','curl'],
       extra_link_args=['../lib/argus_common.a','../lib/argus_client.a','../lib/argus_parse.a'],
    )

setup (name = 'argusWgan',
       version = '0.1',
       author  = 'Carter Bullard',
       author_email='carter@qosient.com',
       description = 'Time functions from argus client library',
       ext_modules = [argusWgan],
       py_modules = ["argusWgan"],
    )
