from cryptography.hazmat.primitives import padding, ciphers
from cryptography.hazmat.backends import default_backend

def encrypt_AES_CBC(data: bytearray, derive_key: bytearray, iv: bytearray) -> bytearray:
    """
    Encrypts a data message using AES in CBC mode.

    .. note::
        The data, derive_key and iv must have the 'utf-8' encoding. 

    Parameters
    ----------
        data : bytearray
            The message to encrypt using AES in CBC mode.
        derive_key : bytearray
            The 64-byte derived key extracted from the password and salt.
            The first 32 bytes are the AES key.
        iv : bytearray
            The initialization vector (IV) to use in AES-CBC mode.
            Must be 16 bytes long.

    Returns
    -------
        ciphertext: bytearray
            The encrypted message.

    Raises
    ------
        TypeError
            If a given argument is not a `bytearray` instance.
        ValueError
            If the `derive_key` isn't 64 bytes long or the `iv` isn't 16 bytes long.
    """
    if not isinstance(data, bytearray):
        raise TypeError('Parameter data is not bytearray instance.')
    if not isinstance(derive_key, bytearray):
        raise TypeError('Parameter derive_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')

    if len(derive_key) != 64:
        raise ValueError(f'{derive_key=} is not 64 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')
    
    padder = padding.PKCS7(128).padder()  
    cipher = ciphers.Cipher(ciphers.algorithms.AES(derive_key[:32]), ciphers.modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = bytearray(encryptor.update(padded_data) + encryptor.finalize())
    return ciphertext
