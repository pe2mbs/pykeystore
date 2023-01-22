# -*- coding: utf-8 -*-
"""Main webapp application package."""
#
# pykeystore package
# Copyright (C) 2023 Marc Bertens-Nguyen <m.bertens@pe2mbs.nl>
#
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Library General Public License GPL-2.0-only
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
from setuptools import setup, find_packages


setup(
    name            = 'pykeystore',
    description     = 'Python keystore',
    author          = 'Marc Bertens-Nguyen',
    version         = "1.1.3",
    author_email    = 'm.bertens@pe2mbs.nl',
    url             = 'https://github.com/pe2mbs/pykeystore',
    packages        = find_packages( include = [ 'pykeystore', 'pykeystore.*' ] ),
    install_requires= [
        'cryptography>=39.0.0',
        'keyring>=23.13.1',
        'chardet'
    ],
    classifiers = [
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography"
    ]
)