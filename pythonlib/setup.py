#!/usr/bin/env python

"""
setup.py file for SWIG argustime
"""

from distutils.core import setup, Extension


argustime = Extension('_argustime',
       sources=['argustime_wrap.c', 'argustime.c'],
       include_dirs=['../include'],
       libraries=['m','GeoIP','z','curl'],
       extra_link_args=['../lib/argus_common.a','../lib/argus_client.a','../lib/argus_parse.a'],
    )

setup (name = 'argustime',
       version = '0.1',
       author  = 'Carter Bullard',
       author_email='carter@qosient.com',
       description = 'Time functions from argus client library',
       ext_modules = [argustime],
       py_modules = ["argustime"],
    )
