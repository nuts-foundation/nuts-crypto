.. _nuts-crypto-howto:

Howto
=====

Using the library
-----------------

.. include:: ../../README.rst
    :start-after: .. inclusion-marker-for-contribution

Building the library
--------------------

To generate the Server stub install some dependencies:

.. code-block:: shell

   go get github.com/deepmap/oapi-codegen/cmd/oapi-codegen

Then run

.. code-block:: shell

   oapi-codegen PATH_TO_NUTS_SPEC/nuts-service-crypto.yaml > pkg/generated/api_gen.go


