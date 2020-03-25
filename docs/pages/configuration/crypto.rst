.. _nuts-crypto-configuration:

Nuts crypto configuration
#########################

.. marker-for-readme

The following configuration parameters are available for the event service.

===================================     ====================    ================================================================================
Key                                     Default                 Description
===================================     ====================    ================================================================================
crypto.storage                          fs                      storage to use, 'fs' for file system
crypto.fspath                           .                       when file system is used as storage, this configures the path where keys are stored
crypto.keytype                          EC-P256                 cryptographic key type to use when generating new keys
===================================     ====================    ================================================================================

As with all other properties for nuts-go, they can be set through yaml:

.. sourcecode:: yaml

    crypto:
       keytype: EC-P256

as commandline property

.. sourcecode:: shell

    ./nuts --crypto.keytype EC-P256

Or by using environment variables

.. sourcecode:: shell

    NUTS_CRYPTO_KEYTYPE=EC-P256 ./nuts

