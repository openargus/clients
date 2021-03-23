#!/usr/bin/env python

"""
setup.py file for SWIG argusWgan
"""

from distutils.core import setup, Extension
import os
import sysconfig
import numpy as np

argusWgan = Extension('_argusWgan',
       extra_compile_args = ['-fPIC','-Wno-deprecated-declarations'], 
       sources=['argusWgan_wrap.c', 'argusWgan.c'],
       include_dirs=['../include', '/usr/local/include', np.get_include(), '/Users/carter/tensorflow_venv/lib/python3.8/site-packages/tensorflow/include'],
       libraries=['m','GeoIP','z','curl','dl','tensorflow_framework'],
       extra_link_args=['-L/Users/carter/tensorflow_venv/lib/python3.8/site-packages/tensorflow/','../lib/argus_common.a','../lib/argus_client.a','../lib/argus_parse.a'],
    )

setup (name = 'argusWgan',
       version = '0.2',
       author  = 'Carter Bullard',
       author_email='carter@qosient.com',
       description = 'Time functions from argus client library',
       ext_modules = [argusWgan, Extension('_argusWgan', ['argusWgan.c'])],
       py_modules = ["argusWgan"],
    )
