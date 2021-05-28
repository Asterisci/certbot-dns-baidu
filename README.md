# Baidu Cdn DNS Authenticator plugin for Certbot

A certbot dns plugin to obtain certificates using baidu cdn.

## Obtain Baidu Cdn AccessKey And SecretKey

[https://su.baidu.com/console/index.html#/accountconfig](https://su.baidu.com/console/index.html#/accountconfig)

## Install

```bash
pip install certbot-dns-baidu
```

Or manually:
```bash
git clone https://github.com/chaoers/certbot-dns-baidu.git
cd certbot-dns-baidu
sudo python setup.py install
```

## Credentials File

An example `credentials.ini` file:

```ini
certbot_dns_baidu:dns_baidu_access_key = 12345678
certbot_dns_baidu:dns_baidu_secret_key = 1234567890abcdef1234567890abcdef
```

```bash
chmod 600 /path/to/credentials.ini
```

## Obtain Certificates

```bash
certbot certonly -a certbot-dns-baidu:dns-baidu \
    --certbot-dns-baidu:dns-baidu-credentials /path/to/credentials.ini \
    -d example.com \
    -d "*.example.com"
```
