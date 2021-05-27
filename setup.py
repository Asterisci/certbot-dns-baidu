import sys

from setuptools import setup
from setuptools import find_packages


version = '0.38.1'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'acme>=0.21.1',
    'certbot>=0.21.1',
    'dns-lexicon',
    'mock',
    'setuptools',
    'zope.interface',
]

setup(
    name='certbot-dns-baidu',
    version=version,
    description="Baidu DNS Authenticator plugin for Certbot",
    url='https://github.com/chaoers/certbot-dns-baidu',
    author="Asterisk",
    author_email='fanguofan@asteriscum.cn',
    license='GNU General Public License v3.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'certbot.plugins': [
            'dns-baidu = certbot_dns_baidu.dns_baidu:Authenticator',
        ],
    },
    test_suite='certbot_dns_baidu',
)
