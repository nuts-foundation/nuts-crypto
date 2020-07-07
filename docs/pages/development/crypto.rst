.. _nuts-crypto-development:

Nuts crypto development
#######################

.. marker-for-readme

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