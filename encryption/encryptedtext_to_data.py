from typing import Optional
from .compute_iteration_from_pin import compute_iteration_from_pin
from .create_derive_key import create_derive_key
from .delete_bytearray import delete_bytearray
from .extract_cryptography_components import extract_cryptography_components
from .verify_key import verify_key
from .decrypt_AES_CBC import decrypt_AES_CBC

def encryptedtext_to_data(encryptedtext: bytearray, password: bytearray, *, 
                          pin: Optional[bytearray] = None, 
                          iterations: int = 100_000,
                          Nmin: int = 100_000,
                          Nmax: int = 10_000_000
                          ) -> (bool, int, bytearray):
    """
    encryptedtext_to_data decrypt the encrypted text.

    If the process does not encounter an error, then the first return argument will be False, 
    the second will be 0 and the third will be the decrypted data. 

    If the process encounters an error, then the first return argument will be True, the 
    second will be a number indicating the error encountered and the third an empty bytearray.

    .. note::
        - error = 0 : no error.
        - error = 1 : encryptedtext password or pin parameters are not bytearray instance.
        - error = 2 : iterations is not a positive integer.
        - error = 3 : Nmin or Nmax are not positive integer and not 0 < Nmin < Nmax.
        - error = 4 : encryptedtext not contains at least 80 bytes.
        - error = 5 : The password, the pin are not correct or the encryptedtext has been modified.

    .. note::
        The password and pin will be deleted correctly in the function if no error occured.

    Parameters
    ----------
        encryptedtext : bytearray
            The encrypted text. Must contain at least 80 bytes.
        password : bytearray
            The user password.
        pin : Optional[bytearray]
            The user pin.
            If pin is None, the number of iterations is set by iterations parameter.
            Else, the number of iterations is set by the pin, Nmin and Nmax parameters.
            The default is None.
        iterations: int
            If pin is None, The number of iteration to derive the key using PBKDF2.
            The default is 100_000.
        Nmin : int
            If pin is not None, The minimum number of iteration to derive the key using PBKDF2.
            The default is 100_000.
        Nmax : int
            If pin is not None, The maximum number of iteration to derive the key using PBKDF2.
            The default is 100_000.

    Returns
    -------
        error_encountered : bool
            If the process encoutered an error.
        error : int
            The type of the error. See the note.
        data : bytearray
            The decrypting message using AES in CBC mode.

    """
    if (not isinstance(encryptedtext, bytearray)) or (not isinstance(password, bytearray)) or ((pin is not None) and (not isinstance(pin, bytearray))):
        error_encountered = True
        error = 1
        data = bytearray("".encode('utf-8'))
        return error_encountered, error, data
    if (pin is None) and (not (isinstance(iterations, int) and iterations > 0)):
        error_encountered = True
        error = 2
        data = bytearray("".encode('utf-8'))
        return error_encountered, error, data
    if (pin is not None) and (not (isinstance(Nmin, int) and isinstance(Nmax, int) and 0 < Nmin < Nmax)):
        error_encountered = True
        error = 3
        data = bytearray("".encode('utf-8'))
        return error_encountered, error, data
    if len(encryptedtext) < 80:
        error_encountered = True
        error = 4
        data = bytearray("".encode('utf-8'))
        return error_encountered, error, data
    # Encryption
    if pin is not None:
        iterations = compute_iteration_from_pin(pin, Nmin=Nmin, Nmax=Nmax)
    iv, salt, expected_hmac, ciphertext = extract_cryptography_components(encryptedtext)
    derive_key = create_derive_key(password, salt, iterations)
    if not verify_key(derive_key, iv, ciphertext, expected_hmac):
        error_encountered = True
        error = 5
        data = bytearray("".encode('utf-8'))
        return error_encountered, error, data
    data = decrypt_AES_CBC(ciphertext, derive_key, iv)
    # Deleting from memory all critical data for security
    delete_bytearray(password)
    delete_bytearray(pin)
    delete_bytearray(derive_key)
    del iterations
    return False, 0, data