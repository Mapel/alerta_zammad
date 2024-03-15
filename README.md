Zammad Plugin
================


Create tickets in Zammad.

Installation
------------

Clone the GitHub repo and run:

    $ python setup.py install

Or, to install remotely from GitHub run:

    $ pip install git+https://github.com/mapel/alerta_zammad

Note: If Alerta is installed in a python virtual environment then plugins
need to be installed into the same environment for Alerta to dynamically
discover them.

Configuration
-------------

Add `zammad` to the list of enabled `PLUGINS` in `alertad.conf` server
configuration file and set plugin-specific variable in the
server configuration file or the environment variables:


```python
PLUGINS = ['zammad']
ZAMMAD_URL = ''  # default="Not configured"
ZAMMAD_API_TOKEN = '' # default="Not Set"
ZAMMAD_CUSTOMER_MAIL = '' # default="Not Set"
ZAMMAD_ALLOWED_SEVERITIES = 'security,critical,major' # list of allowed severity to (re)open / default: 'security,critical,major'
```


References
----------



License
-------

Copyright (c) 2024 DKDS.