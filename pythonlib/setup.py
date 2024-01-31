#!/usr/bin/env python

"""
setup.py file for SWIG argusPython
"""

from distutils.core import setup, Extension
import os
import sysconfig
import numpy as np

argusPython = Extension('_argusPython',
       extra_compile_args = ['-fPIC','-Wno-deprecated-declarations'], 
       sources=['argusPython_wrap.c', 'argusPython.c'],
       include_dirs=['../include', '/usr/local/include', np.get_include()],
       libraries=['m','z', 'curl','dl','tensorflow_framework'],
       extra_link_args=['-L../../../Library/Python/2.7/lib/python/site-packages/tensorflow_core','../lib/argus_common.a','../lib/argus_client.a','../lib/argus_parse.a']
    )

setup (name = 'argusPython',
       version = '0.2',
       author  = 'Carter Bullard',
       author_email='carter@qosient.com',
       description = 'Time functions from argus client library',
       ext_modules = [argusPython, Extension('_argusPython', ['argusPython.c'])],
       py_modules = ["argusPython"],
    )
