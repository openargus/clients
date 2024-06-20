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
       libraries=['m','z', 'curl','dl'],
       extra_link_args=['../lib/argus_common.a','../lib/argus_client.a','../lib/argus_parse.a']
    )

setup (name = 'argusPython',
       version = '0.2',
       url="https://github.com/openargus/argusPython/",
       author  = 'Carter Bullard',
       author_email='carter@qosient.com',
       description = 'Read, process and time functions from argus client library',
       ext_modules = [argusPython, Extension('_argusPython', ['argusPython.c'])],
       py_modules = ["argusPython"],
    )
