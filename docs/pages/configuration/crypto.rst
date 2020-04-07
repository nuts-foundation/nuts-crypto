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
crypto.keysize                          2048                    number of bits to use when creating new RSA keys
crypto.signature                        plain-rsa               signature format to use when signing data (options: plain-rsa, jws)
                                                                'plain-rsa' is the format currently in use but since we want to migrate to JWS
                                                                in future 'jws' was added. You should not switch to 'jws' unless everyone else
                                                                in the network supports it.
===================================     ====================    ================================================================================

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

