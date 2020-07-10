nuts-crypto
###########

Go crypto lib for Nuts service space

.. image:: https://circleci.com/gh/nuts-foundation/nuts-crypto.svg?style=svg
    :target: https://circleci.com/gh/nuts-foundation/nuts-crypto
    :alt: Build Status

.. image:: https://readthedocs.org/projects/nuts-crypto/badge/?version=latest
    :target: https://nuts-documentation.readthedocs.io/projects/nuts-crypto/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-crypto/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-crypto

.. image:: https://api.codeclimate.com/v1/badges/72b0fb803a2716c10128/maintainability
   :target: https://codeclimate.com/github/nuts-foundation/nuts-crypto/maintainability
   :alt: Maintainability

The crypto module is written in Go and should be part of nuts-go as an engine.

Dependencies
************

This projects is using go modules, so version > 1.12 is recommended. 1.10 would be a minimum.

Running tests
*************

Tests can be run by executing

.. code-block:: shell

    go test ./...

Building
********

This project is part of https://github.com/nuts-foundation/nuts-go. If you do however would like a binary, just use ``go build``.

The server API is generated from the open-api spec:

.. code-block:: shell

    oapi-codegen -generate server,client,types -package api docs/_static/nuts-service-crypto.yaml > api/generated.go

Generating mocks
****************

.. code-block:: shell

   mockgen -destination=test/mock/client.go -package=mock -source=pkg/client.go Client

README
******

The readme is auto-generated from a template and uses the documentation to fill in the blanks.

.. code-block:: shell

    ./generate_readme.sh

This script uses ``rst_include`` which is installed as part of the dependencies for generating the documentation.

Documentation
*************

To generate the documentation, you'll need python3, sphinx and a bunch of other stuff. See :ref:`nuts-documentation-development-documentation`
The documentation can be build by running

.. code-block:: shell

    /docs $ make html

The resulting html will be available from ``docs/_build/html/index.html``

Configuration
=============

The following configuration parameters are available:

=============  ==============  ==============================================================================================================================
Key            Default         Description
=============  ==============  ==============================================================================================================================
address        localhost:1323  Interface and port for http server to bind to, default: localhost:1323
clientTimeout  10              Time-out for the client in seconds (e.g. when using the CLI), default: 10
fspath         ./              When file system is used as storage, this configures the path where key material and the truststore are persisted, default: ./
keysize        2048            Number of bits to use when creating new RSA keys, default: 2048
mode                           Server or client, when client it uses the HttpClient, default:
storage        fs              Storage to use, 'fs' for file system, default: fs
=============  ==============  ==============================================================================================================================

As with all other properties for nuts-go, they can be set through yaml:

.. sourcecode:: yaml

    crypto:
       keysize: 4096

as commandline property

.. sourcecode:: shell

    ./nuts --crypto.keysize 4096

Or by using environment variables

.. sourcecode:: shell

    NUTS_CRYPTO_KEYSIZE=4096 ./nuts

