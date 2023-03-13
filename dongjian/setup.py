#!/usr/bin/env python
import ast
import os
import re
import sys
from io import open

from setuptools import find_packages, setup

setup_dir = os.path.abspath(os.path.dirname(__file__))


extra_requirements = {
    "dev": ["tox", "flake8", "check-manifest", "mock", "pytest", "pytest-bdd", "netifaces", "ipaddress", "sphinx",
            "pykd"]
}

if sys.version_info >= (3, 6):
    extra_requirements["dev"] += ["black"]


setup(
    name="DongJian",
    version="0.0.1.0",
    description="A Fuzzing Test Tool Named DongJian Support Many Protocols",
    maintainer="Josh Woo from cetcsc",
    maintainer_email="970642163@qq.com",
    url="www.civdp.com",
    license="MIT",
    packages=find_packages(exclude=["DongJian-result", "static", "templates", "listen.py", "getfilename.py", "get_ipv6_addr.py"]),
    package_data={"web_ui": ["server.crt", "server.key", "uwsgi.ini", "uwsgi.pid",
                               "templates/*", "static/*", "static/css/*", "static/js/*", "static/img/*","static/data/*",
                               "static/layer/*", "static/layer/theme/default/*", "static/layui/*",
                               "static/layui/lay/modules/*", "static/layui/images/face/*",
                               "static/layui/font/*", "static/layui/css/*", "static/layui/css/modules/*",
                               "static/layui/css/modules/layer/default/*", "static/layui/css/modules/laydate/default/*"]},
    install_requires=[
        "attrs",
        "backports.shutil_get_terminal_size",
        "click",
        "colorama",
        "Flask",
        "future",
        "impacket",
        "ldap3==2.5.1",
        "psutil==5.6.7",
        "pyserial",
        "pydot",
        "six",
        "tornado~=5.0",
        "DBUtils==1.3",
        "pymysql",
        "pymongo",
        "libscrc",
        "python-docx"
    ],
    extras_require=extra_requirements,
    entry_points={"console_scripts": ["djfuzz=web_ui.djfuzz:main", "startwebapp=web_ui.startwebapp:main"]},
)
