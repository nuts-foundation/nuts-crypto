.. _nuts-crypto-monitoring:

Nuts certificate monitoring
###########################

One of the challenges with using certificates and key management is to renew them in time.
The first step in the process is to identify which certificates are about to expire and alert an administrator about this fact.
Therefore some prometheus metrics are provided which give the amount of certificates about to expire within a certain period.

Prometheus metrics
******************

.. code-block:: text

    # HELP nuts_crypto_certificate_expiry a gauge on the amount of certificates about to expire.
    # TYPE nuts_crypto_certificate_expiry gauge
    nuts_crypto_certificate_expiry{period="day"} 0
    nuts_crypto_certificate_expiry{period="week"} 0
    nuts_crypto_certificate_expiry{period="4_weeks"} 1
