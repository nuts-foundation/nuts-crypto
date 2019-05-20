.. _nuts-crypto-howto:

Howto
=====

Using the library
-----------------

.. include:: ../../README.rst
    :start-after: .. inclusion-marker-for-contribution

Building the library
--------------------

Nuts uses Go modules, check out https://github.com/golang/go/wiki/Modules for more info on Go modules.

To generate the Server stub install some dependencies:

.. code-block:: shell

   go get github.com/deepmap/oapi-codegen/cmd/oapi-codegen

Then run

.. code-block:: shell

   oapi-codegen -package api -generate server PATH_TO_NUTS_SPEC/nuts-service-crypto.yaml > pkg/api/api_gen.go
   oapi-codegen -package client -generate client PATH_TO_NUTS_SPEC/nuts-service-crypto.yaml > pkg/client/client_gen.go


