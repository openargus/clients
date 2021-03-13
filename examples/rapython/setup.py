from distutils.core import setup, Extension

module1 = Extension('argusWgan',
                    sources = ['argusWgan.c'])

setup (name = 'PackageName',
       version = '1.0',
       description = 'This is a demo package',
       ext_modules = [module1])
