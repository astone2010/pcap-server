"""The two exceptions the rest of the app sees from built-in HTTPS."""


class AcmeError(Exception):
    """Issuance, storage or serving failed; the message is written for an operator."""


class AcmeBusy(AcmeError):
    """Another certificate request holds the lock."""
