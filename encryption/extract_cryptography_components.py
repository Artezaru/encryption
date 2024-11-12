def extract_cryptography_components(encryptedtext: bytearray) -> (bytearray, bytearray, bytearray, bytearray):
    """
    Extracts the IV, salt, expected HMAC, and ciphertext from the encrypted text.

    Parameters
    ----------
        encryptedtext : bytearray
            The encrypted text. Must contain at least 80 bytes.

    Returns
    -------
        tuple
            A tuple containing the IV, salt, expected HMAC, and ciphertext.

    Raises
    ------
        TypeError
            If the argument is not a `bytearray` instance.
        ValueError
            If the bytearray contains fewer than 48 bytes.
    """
    if not isinstance(encryptedtext, bytearray):
        raise TypeError('Parameter encryptedtext is not bytearray instance.')
    if len(encryptedtext) < 80:
        raise ValueError(f'encryptedtext does not contain more than 80 bytes.') 

    iv = encryptedtext[0:16]
    salt = encryptedtext[16:48]
    expected_hmac = encryptedtext[48:80]
    ciphertext = encryptedtext[80:]
    return iv, salt, expected_hmac, ciphertext