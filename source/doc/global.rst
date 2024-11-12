
Notations and Examples
======================

Parameter Notations used in the AES encryption functions
--------------------------------------------------------

- **data (bytearray)**: The message to encrypt using AES in CBC mode.
- **password (bytearray)**: The user's password used to encrypt and decrypt data.
- **pin (bytearray)**: The user's PIN used to set the number of iterations to derive the key.
- **salt (bytearray)**: The 32-byte salt used to generate the derived key.
- **derive_key (bytearray)**: The 64-byte derived key extracted from the password and salt. The first 32 bytes are the key used for encryption, and the last 64 bytes are the HMAC key (`key_hmac`).
- **iv (bytearray)**: The initialization vector (IV) used in AES-CBC mode. It must be 16 bytes long.
- **ciphertext (bytearray)**: The encrypted message to decrypt using AES in CBC mode. The ciphertext is the encryption of the `data` using the encryption key.
- **expected_hmac (bytearray)**: The 32-byte expected HMAC constructed using the `key_hmac`, `iv`, and `ciphertext`. This HMAC is used to verify if the `derive_key` is correct.
- **encryptedtext (bytearray)**: The concatenation of `iv + salt + expected_hmac + ciphertext`. This is the final encrypted text format used for transmitting or storing the encrypted data.

Basic Usage of encryption:
--------------------------

.. code-block:: python

    # ===================
    # Encrypting the data
    # ===================
    data = bytearray("Hello World".encode('utf-8'))
    password = bytearray("password".encode('utf-8'))
    pin = bytearray("pin".encode('utf-8')) # Just to be on the safe side, you can use iterations= directly. 
    iterations = compute_iteration_from_pin(pin)
    salt = random_bytearray(32)
    iv = random_bytearray(16)
    iterations = compute_iteration_from_pin(pin)
    derive_key = create_derive_key(password, salt, iterations)
    ciphertext = encrypt_AES_CBC(data, derive_key, iv)
    expected_hmac = create_hmac(derive_key, iv, ciphertext)
    encryptedtext = create_encryptedtext(iv, salt, expected_hmac, ciphertext)
    # Deleting from memory all critical data for security
    delete_bytearray(data)
    delete_bytearray(password)
    delete_bytearray(pin)
    delete_bytearray(derive_key)
    del iterations

    # ============================
    # Decrypting the encryptedtext
    # ============================
    encryptedtext = encryptedtext
    password = bytearray("password".encode('utf-8'))
    pin = bytearray("pin".encode('utf-8')) # Just to be on the safe side, you can use iterations= directly. 
    iterations = compute_iteration_from_pin(pin)
    iv, salt, expected_hmac, ciphertext = extract_cryptography_components(encryptedtext)
    derive_key = create_derive_key(password, salt, iterations)
    if not verify_key(derive_key, iv, ciphertext, expected_hmac):
        print("The derive key is not correct. - The user password or pin is not correct. - The encryptedtext has been modified.")
    else:
        data = decrypt_AES_CBC(ciphertext, derive_key, iv)
        print(f"Decrypted data : {data}")
    # Deleting from memory all critical data for security
    delete_bytearray(password)
    delete_bytearray(pin)
    delete_bytearray(derive_key)
    del iterations

