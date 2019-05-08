nuts-crypto
===========

Go crypto lib for Nuts service space

.. image:: https://travis-ci.org/nuts-foundation/nuts-crypto.svg?branch=master
    :target: https://travis-ci.org/nuts-foundation/nuts-crypto
    :alt: Build Status

.. image:: https://readthedocs.org/projects/nuts-crypto/badge/?version=latest
    :target: https://nuts-documentation.readthedocs.io/projects/nuts-crypto/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-crypto/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-crypto

.. inclusion-marker-for-contribution

Nuts-crypto is intended to be used as a library within an executable. It abstracts the key storage layer and provides helper function for encryption and decryption.

Installation
------------

.. code-block:: shell

   go get github.com/nuts-foundation/nuts-crypto

Configuration
-------------

The lib is configured using `Viper <https://github.com/spf13/viper>`_, thus it will work well with `Cobra <https://github.com/spf13/cobra>`_ as well.
Command flags can be added to a command using the `config.Flags()` helper function.

.. code-block:: go

   cmd := newRootCommand()
   cmd.Flags().AddFlagSet(Flags())

The following config options are available:

.. code-block:: shell

   Flags:
      --cryptobackend string   backend to use, 'fs' for file system (default) (default "fs")
      --fspath string          when file system is used as backend, this configures the path where keys are stored (default .) (default "./")

Usage
-----

.. code-block:: go

   client, err := crypto.NewCryptoClient()


