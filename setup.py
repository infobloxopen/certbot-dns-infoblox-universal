#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

with open("README.md") as readme_file:
    readme = readme_file.read()

setup(
    name="certbot-dns-infoblox-universal",
    version="0.1.0",
    description="Certbot plugin for Infoblox Universal DDI for DNS-01 Challenge",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Infoblox",
    url="https://github.com/infobloxopen/certbot-dns-infoblox-universal",
    packages=["certbot_dns_infoblox_universal"],
    package_dir={"certbot_dns_infoblox_universal": "certbot_dns_infoblox_universal"},
    install_requires=[
        "universal-ddi-python-client>=0.1.0",
        "zope.interface>=7.1.1",
    ],
    entry_points={
        "certbot.plugins": [
            "dns-infoblox-universal = certbot_dns_infoblox_universal.dns_infoblox_universal:Authenticator",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
