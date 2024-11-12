import hmac
import hashlib
from .delete_bytearray import delete_bytearray

def verify_key(derive_key: bytearray, iv: bytearray, ciphertext: bytearray, expected_hmac: bytearray) -> bool:
    """
    Verifies if the derived 64-byte key matches the expected HMAC.

    Parameters
    ----------
        derive_key : bytearray
            The 64-byte derived key.
        iv : bytearray
            The 16-byte long initialization vector used for encryption.
        ciphertext : bytearray
            The encrypted message.
        expected_hmac : bytearray
            The expected 32-byte HMAC value.

    Returns
    -------
        bool
            True if the derived key matches the HMAC, False otherwise.

    Raises
    ------
        TypeError
            If any argument is not a `bytearray` instance.
        ValueError
            If the derived key isn't 48 bytes, the IV isn't 16 bytes, or the HMAC isn't 32 bytes.
    """
    if not isinstance(derive_key, bytearray):
        raise TypeError('Parameter derive_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')
    if not isinstance(ciphertext, bytearray):
        raise TypeError('Parameter ciphertext is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')
    if len(derive_key) != 64:
        raise ValueError(f'{derive_key=} is not 64 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')
    if len(expected_hmac) != 32:
        raise ValueError(f'{expected_hmac=} is not 32 bytes long.')
    
    hmac_key = derive_key[32:]
    hmac_value = bytearray(hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest())
    check = hmac.compare_digest(expected_hmac, hmac_value)
    # Securely delete the hmac_key
    delete_bytearray(hmac_key)
    delete_bytearray(hmac_value)
    return check