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

.. include:: docs/pages/development/crypto.rst
    :start-after: .. marker-for-readme

Configuration
=============

The following configuration parameters are available:

.. include:: README_options.rst

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
