def create_encryptedtext(iv: bytearray, salt: bytearray, expected_hmac: bytearray, ciphertext: bytearray) -> bytearray:
    """
    Creates a bytearray containing all the information needed to decrypt the data.

    Parameters
    ----------
        iv : bytearray
            The 16-byte initialization vector used for encryption.
        salt : bytearray
            The 32-byte salt used to generate the derived key.
        expected_hmac : bytearray
            The 32-byte expected HMAC.
        ciphertext : bytearray
            The encrypted message.

    Returns
    -------
        encryptedtext : bytearray
            The concatenated bytearray containing `iv + salt + expected_hmac + ciphertext`.

    Raises
    ------
        TypeError
            If any argument is not a `bytearray` instance.
        ValueError
            If any of the components (salt, iv, hmac) are not the correct length.
    """
    if not isinstance(iv, bytearray):
        raise TypeError('Parameter iv is not bytearray instance.')
    if not isinstance(salt, bytearray):
        raise TypeError('Parameter salt is not bytearray instance.')
    if not isinstance(expected_hmac, bytearray):
        raise TypeError('Parameter expected_hmac is not bytearray instance.')
    if not isinstance(ciphertext, bytearray):
        raise TypeError('Parameter ciphertext is not bytearray instance.')
    if len(iv) != 16:
        raise ValueError(f'{iv=} is not 16 bytes long.') 
    if len(salt) != 32:
        raise ValueError(f'{salt=} is not 32 bytes long.') 
    if len(expected_hmac) != 32:
        raise ValueError(f'{expected_hmac=} is not 32 bytes long.')

    return iv + salt + expected_hmac + ciphertext