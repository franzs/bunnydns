bunnydns
========

A Python SDK for the `Bunny.net DNS API <https://docs.bunny.net/api-reference/core/dns-zone/>`_.

Installation
------------

.. code-block:: bash

   pip install bunnydns

Quick Start
-----------

.. code-block:: python

   from bunnydns import BunnyDNS

   client = BunnyDNS(access_key="your-api-key")
   zones = client.list_dns_zones()
   for zone in zones.items:
       print(zone.domain)

.. toctree::
   :maxdepth: 3
   :caption: API Reference

   api/client
   api/models
   api/enums
   api/exceptions
