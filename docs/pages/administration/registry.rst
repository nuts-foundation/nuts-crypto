.. _nuts-registry-administration:

Nuts Crypto Administration
############################

This administration guide will help you to achieve the following goals:

- :ref:`generate-vendorca-csr` which is required for registering your vendor.

.. _generate-vendorca-csr-label:

1. Generating vendor CA certificate CSR
=======================================

This command generates a vendor CA certificate CSR for the current vendor. The resulting CSR should then be signed
(in other words, a certificate is issued) by the Network Authority. Upon receiving the certificate it is used to register
the vendor.

If there is a key pair in the crypto module for the vendor it will be associated with the CSR (and thus the issued certificate).
It will be generated if it doesn't exist.

To generate the CSR you need your vendor's name as it will end up as *Subject* in the CSR.

The syntax of this command is as follows:

.. code-block:: shell

    ./nuts crypto generate-vendor-csr <name> <domain>

To register vendor "BecauseWeCare B.V.", run the following command:

.. code-block:: shell

    NUTS_MODE=cli ./nuts crypto generate-vendor-csr "BecauseWeCare B.V."

If the command completes successfully, it should output the CSR (as PEM-encoded PKCS#10). This CSR should then be sent
to the Network Authority. Upon receiving the issued certificate proceed with :ref:`register-vendor-label`.
