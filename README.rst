aioquic
=======

Content of this forked repository
--------------------

This is a modified variant of ``aioquic`` with the intention of studying the performance of different `EFM algorithms <https://datatracker.ietf.org/doc/draft-mdt-ippm-explicit-flow-measurements/>`_ algorithms.


Publication
....

It has been created in the context of and used for the following publication:

* Ike Kunze, Klaus Wehrle, and Jan Rüth: *L, Q, R, and T - Which Spin Bit Cousin Is Here to Stay?*. In ANRW '21: Proceedings of the Applied Networking Research Workshop

If you use any portion of our work, please consider citing our publication.

.. code-block::

    @Inproceedings{2021-kunze-efm-evaluation,
    author = {Kunze, Ike and Wehrle, Klaus and R{\"u}th, Jan},
    title = {L, Q, R, and T - Which Spin Bit Cousin Is Here to Stay?},
    booktitle = {ANRW '21: Proceedings of the Applied Networking Research Workshop},
    year = {2021},
    month = {July},
    doi = {10.1145/3472305.3472319}
    }


Modifications of this variant
....
- There is an additional byte after the `Spin Bit` (measurement header)
    - It is enabled by default
    - To disable the measurement header:
        1. Set the `Active` attribute of the `Measurement_Headers` class in `src/aioquic/quic/__init__.py` to False
        2. Set the `MeasurementHeaders` variable in `src/aioquic/_crypto.c` to something other than 1
- The header protection has been removed from the two reserved bits in the short header as well as the measurement header (if it is enabled)
- Datagram packets no longer count towards the `in flight` counting, i.e., congestion-control is effectively disabled (`src/aioquic/quic/packet.py`)
- `src/aioquic/quic/packet_builder.py` contains **tested** end-host logic for the EFM variants focussing on loss (L|Q|R|T)
    - There are also implementations for EFM variants focussing on delay (two variants of the delay bit, one variant for the VEC). These are **not tested** yet. Please use with caution.
- By default, if the measurement header is active, **all** implemented EFM variants are active and are added to each outgoing packet (see `src/aioquic/quic/packet_builder.py` : `_end_packet`)
    - If the measurement header is disabled, it is possible to precisely define which EFM variants should be mapped onto the two reserved bits of the real QUIC short header (see `src/aioquic/quic/configuration.py`)

- Hooks for the EFM variants
    - All EFM variants are hooked at the datagram reception in `src/aioquic/quic/connection.py` 
    - The LBit implementation is further embedded in the loss detection in `src/aioquic/quic/recovery.py` 


Original README
---------------

|rtd| |pypi-v| |pypi-pyversions| |pypi-l| |tests| |codecov| |black|

.. |rtd| image:: https://readthedocs.org/projects/aioquic/badge/?version=latest
    :target: https://aioquic.readthedocs.io/

.. |pypi-v| image:: https://img.shields.io/pypi/v/aioquic.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/aioquic.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |pypi-l| image:: https://img.shields.io/pypi/l/aioquic.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |tests| image:: https://github.com/aiortc/aioquic/workflows/tests/badge.svg
    :target: https://github.com/aiortc/aioquic/actions

.. |codecov| image:: https://img.shields.io/codecov/c/github/aiortc/aioquic.svg
    :target: https://codecov.io/gh/aiortc/aioquic

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/python/black

What is ``aioquic``?
--------------------

``aioquic`` is a library for the QUIC network protocol in Python. It features
a minimal TLS 1.3 implementation, a QUIC stack and an HTTP/3 stack.

QUIC standardisation is not finalised yet, but ``aioquic`` closely tracks the
specification drafts and is regularly tested for interoperability against other
`QUIC implementations`_.

To learn more about ``aioquic`` please `read the documentation`_.

Why should I use ``aioquic``?
-----------------------------

``aioquic`` has been designed to be embedded into Python client and server
libraries wishing to support QUIC and / or HTTP/3. The goal is to provide a
common codebase for Python libraries in the hope of avoiding duplicated effort.

Both the QUIC and the HTTP/3 APIs follow the "bring your own I/O" pattern,
leaving actual I/O operations to the API user. This approach has a number of
advantages including making the code testable and allowing integration with
different concurrency models.

Features
--------

- QUIC stack conforming with draft-28
- HTTP/3 stack conforming with draft-28
- minimal TLS 1.3 implementation
- IPv4 and IPv6 support
- connection migration and NAT rebinding
- logging TLS traffic secrets
- logging QUIC events in QLOG format
- HTTP/3 server push support

Requirements
------------

``aioquic`` requires Python 3.6 or better, and the OpenSSL development headers.

Linux
.....

On Debian/Ubuntu run:

.. code-block:: console

   $ sudo apt install libssl-dev python3-dev

On Alpine Linux you will also need the following:

.. code-block:: console

   $ sudo apt install bsd-compat-headers libffi-dev

OS X
....

On OS X run:

.. code-block:: console

   $ brew install openssl

You will need to set some environment variables to link against OpenSSL:

.. code-block:: console

   $ export CFLAGS=-I/usr/local/opt/openssl/include
   $ export LDFLAGS=-L/usr/local/opt/openssl/lib

Windows
.......

On Windows the easiest way to install OpenSSL is to use `Chocolatey`_.

.. code-block:: console

   > choco install openssl

You will need to set some environment variables to link against OpenSSL:

.. code-block:: console

  > $Env:INCLUDE = "C:\Progra~1\OpenSSL-Win64\include"
  > $Env:LIB = "C:\Progra~1\OpenSSL-Win64\lib"

Running the examples
--------------------

`aioquic` comes with a number of examples illustrating various QUIC usecases.

You can browse these examples here: https://github.com/aiortc/aioquic/tree/main/examples

License
-------

``aioquic`` is released under the `BSD license`_.

.. _read the documentation: https://aioquic.readthedocs.io/en/latest/
.. _QUIC implementations: https://github.com/quicwg/base-drafts/wiki/Implementations
.. _cryptography: https://cryptography.io/
.. _Chocolatey: https://chocolatey.org/
.. _BSD license: https://aioquic.readthedocs.io/en/latest/license.html
