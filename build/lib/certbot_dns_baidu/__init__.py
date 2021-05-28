"""
The `~certbot_dns_baidu.dns_baidu` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the BaiduCdn REST API.


Named Arguments
---------------

========================================  =====================================
``--dns-baidu-credentials``           BaiduCdn Remote API credentials_
                                          INI file. (Required)
``--dns-baidu-propagation-seconds``   The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 120)
========================================  =====================================

Credentials File
-----------

An example ``credentials.ini`` file:

.. code-block:: ini

    certbot_dns_baidu:dns_baidu_access_key = 12345678
    certbot_dns_baidu:dns_baidu_secret_key = 1234567890abcdef1234567890abcdef


.. code-block:: bash
    chmod 600 /path/to/credentials.ini


Obtain Certificates
--------

.. code-block:: bash

    certbot certonly -a certbot-dns-baidu:dns-baidu \
        --certbot-dns-baidu:dns-baidu-credentials /path/to/credentials.ini \
        -d example.com \
        -d "*.example.com"

"""
