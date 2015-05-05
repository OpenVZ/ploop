#! /usr/bin/python

from distutils.core import setup, Extension

extension_mod = Extension('libploop.libploopapi',
	sources=['libploop/libploopmodule.c'],
	include_dirs=['../include', '../lib'],
	library_dirs=['../lib'],
	libraries=['ploop'])

setup(name = 'libploop',
	ext_modules=[extension_mod],
	packages=["libploop"],
	description = 'ploop API',
	)
