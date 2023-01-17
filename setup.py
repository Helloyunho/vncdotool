#!/usr/bin/env python

from setuptools import setup

from vncdotool import __version__

setup(
    name='vncdotool',
    version=__version__,
    description='Command line VNC client',
    install_requires=[
        'Twisted',
        "Pillow",
        "PyCryptodome",
    ],
    tests_require=[
        'pexpect',
    ],
    url='http://github.com/sibson/vncdotool',
    author='Marc Sibson',
    author_email='sibson+vncdotool@gmail.com',
    download_url='',

    entry_points={
        "console_scripts": [
            'vncdo=vncdotool.command:vncdo',
            'vncdotool=vncdotool.command:vncdo',
            'vnclog=vncdotool.command:vnclog',
        ],
    },
    packages=['vncdotool'],

    classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Framework :: Twisted',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Topic :: Multimedia :: Graphics :: Viewers',
          'Topic :: Software Development :: Testing',
    ],

    long_description=open('README.rst').read(),
)
