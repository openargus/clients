#!/usr/bin/env python

"""Build the SWIG argusPython extension against the configured Argus tree."""

from pathlib import Path
import os
import platform
import shlex
import sys

import numpy as np
from setuptools import Extension, setup


if sys.platform == "darwin":
    # Match the extension architecture to the configured static Argus archives.
    os.environ.setdefault("ARCHFLAGS", "-arch %s" % platform.machine())


ROOT = Path(__file__).resolve().parent.parent
libraries = ["m", "z", "curl"]
if sys.platform != "darwin":
    libraries.append("dl")

argus_python = Extension(
    "_argusPython",
    sources=["argusPython_wrap.c", "argusPython.c", "argusPython_reader.c"],
    include_dirs=[str(ROOT / "include"), str(ROOT / "common"), np.get_include()],
    define_macros=[("HAVE_CONFIG_H", "1")],
    extra_compile_args=["-fPIC", "-Wno-deprecated-declarations"],
    extra_objects=[
        str(ROOT / "lib" / "argus_common.a"),
        str(ROOT / "lib" / "argus_client.a"),
    ],
    extra_link_args=shlex.split(os.environ.get("ARGUS_PYTHON_LINK_ARGS", "")),
    libraries=libraries,
)

setup(
    name="argusPython",
    version="1.0.0",
    url="https://github.com/openargus/argus-clients/",
    author="Carter Bullard",
    author_email="carter@qosient.com",
    description="Binary-first Argus record streaming and NumPy batches",
    ext_modules=[argus_python],
    py_modules=["argusPython"],
)
