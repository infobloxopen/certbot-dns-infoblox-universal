certbot-dns-infoblox-universal
====================

Infoblox Universal DNS Authenticator plugin for Certbot

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the Infoblox Remote API.

In order to get a certificate from Let’s Encrypt, you have to demonstrate control over the domain name. Usually, this is done using HTTP where you upload a specific file to your website. Using DNS / Infoblox as a backend, you are no longer required to run a webserver, and can furthermore prove ownership of domain names only accessible internally, and even of wildcard DNS names as, e.g., `*.example.com`.

Note that all certificates issued by Certificate Authorities as, e.g., Let's Encrypt are added to a distributed database called the [certificate transparency logs](https://certificate.transparency.dev/) (searchable at e.g. [crt.sh](https://crt.sh/)). In particular when issuing internal certificates, you should be careful about revealing names of internal servers, etc.


Installation
------------
```
pip install certbot-dns-infoblox-universal
```

Named Arguments
---------------

To start using DNS authentication for Infoblox, pass the following arguments on
certbot's command line:

| Argument                                                                        | Description                                                                                             |
|---------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| ``--authenticator certbot-dns-infoblox-universal:dns-infoblox-universal``       | Select the authenticator plugin (Required)                                                              |
| ``--certbot-dns-infoblox-universal:dns-infoblox-universal-credentials``         | Infoblox remote user credentials INI file. (Default: ``/etc/letsencrypt/infoblox.ini``)                 |
| ``--certbot-dns-infoblox-universal:dns-infoblox-universal-propagation-seconds`` | Waiting time for DNS to propagate before asking the ACME server to verify the DNS record. (Default: 10) |

If you are using certbot >= 1.0, you can skip the `certbot-dns-infoblox:`
in the above arguments.


Credentials
-----------
An example ``credentials.ini`` file:

    #
    # Sample Infoblox INI file
    # Default location /etc/letsencrypt/infoblox.ini
    #
    dns_infoblox_universal_api_key="5f4dcc3b5aa765d61d8327deb882cf99"
    dns_infoblox_universal_view="default"

The path to this file can be provided interactively or using the
``--dns-infoblox-universal-credentials`` command-line argument. Certbot
records the path to this file for use during renewal, but does not store the
file's contents.

**CAUTION:** You should protect these API credentials as you would the
password to your infoblox account. Users who can read this file can use these
credentials to issue arbitrary API calls on your behalf. Users who can cause
Certbot to run using these credentials can complete a ``dns-01`` challenge to
acquire new certificates or revoke existing certificates for associated
domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------
To acquire a single certificate for both ``example.com`` and
``*.example.com``, waiting 100 seconds for DNS propagation:

    certbot certonly \
    --authenticator dns-infoblox-universal \
    --dns-infoblox-universal-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
    --dns-infoblox-universal-propagation-seconds 100 \
    --agree-tos \
    --rsa-key-size 4096 \
    -d 'example.com' \
    -d '*.example.com'