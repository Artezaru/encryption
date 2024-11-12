from cryptography.hazmat.primitives import padding, ciphers
from cryptography.hazmat.backends import default_backend

def decrypt_AES_CBC(ciphertext: bytearray, derive_key: bytearray, iv: bytearray) -> bytearray:
    """
    Decrypts a ciphertext message using AES in CBC mode.

    .. note::
        The ciphertext, derive_key and iv must have the 'utf-8' encoding. 

    Parameters
    ----------
        ciphertext : bytearray
            The message to decrypt using AES in CBC mode.
        derive_key : bytearray
            The key to decrypt the ciphertext. Must be 64 bytes long.
        iv : bytearray
            The initialization vector (IV) to use in AES-CBC mode.
            Must be 16 bytes long.

    Returns
    -------
        data : bytearray
            The decrypted message.

    Raises
    ------
        TypeError
            If a given argument is not a `bytearray` instance.
        ValueError
            If the `derive_key` isn't 64 bytes long or the `iv` isn't 16 bytes long.
    """
    if not isinstance(ciphertext, bytearray):
        raise TypeError('Parameter ciphertext is not bytearray instance.')
    if not isinstance(derive_key, bytearray):
        raise TypeError('Parameter derive_key is not bytearray instance.')
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')
    if len(derive_key) != 64:
        raise ValueError(f'{derive_key=} is not 64 bytes long.') 
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.')
    
    cipher = ciphers.Cipher(ciphers.algorithms.AES(derive_key[:32]), ciphers.modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()  
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize() 
    unpadded_data = bytearray(unpadder.update(decrypted_data) + unpadder.finalize())
    return unpadded_data