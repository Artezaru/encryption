from typing import Optional
from .compute_iteration_from_pin import compute_iteration_from_pin
from .random_bytearray import random_bytearray
from .create_derive_key import create_derive_key
from .encrypt_AES_CBC import encrypt_AES_CBC
from .create_hmac import create_hmac
from .create_encryptedtext import create_encryptedtext
from .delete_bytearray import delete_bytearray

def data_to_encryptedtext(data: bytearray, password: bytearray, *, 
                          pin: Optional[bytearray] = None, 
                          iterations: int = 100_000,
                          Nmin: int = 100_000,
                          Nmax: int = 10_000_000
                          ) -> (bool, int, bytearray):
    """
    data_to_encryptedtext generate the encrypted text.

    If the process does not encounter an error, then the first return argument will be False, 
    the second will be 0 and the third will be the encrypted text. 

    If the process encounters an error, then the first return argument will be True, the 
    second will be a number indicating the error encountered and the third an empty bytearray.

    .. note::
        - error = 0 : no error.
        - error = 1 : data password or pin parameters are not bytearray instance.
        - error = 2 : iterations is not a positive integer.
        - error = 3 : Nmin or Nmax are not positive integer and not 0 < Nmin < Nmax.

    .. note::
        The data, password and pin will be deleted correctly in the function if no error occured.

    Parameters
    ----------
        data : bytearray
            The message to encrypt using AES in CBC mode.
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
        encryptedtext : bytearray
            The encrypted text. 
    """
    if (not isinstance(data, bytearray)) or (not isinstance(password, bytearray)) or ((pin is not None) and (not isinstance(pin, bytearray))):
        error_encountered = True
        error = 1
        encryptedtext = bytearray("".encode('utf-8'))
        return error_encountered, error, encryptedtext
    if (pin is None) and (not (isinstance(iterations, int) and iterations > 0)):
        error_encountered = True
        error = 2
        encryptedtext = bytearray("".encode('utf-8'))
        return error_encountered, error, encryptedtext
    if (pin is not None) and (not (isinstance(Nmin, int) and isinstance(Nmax, int) and 0 < Nmin < Nmax)):
        error_encountered = True
        error = 3
        encryptedtext = bytearray("".encode('utf-8'))
        return error_encountered, error, encryptedtext
    # Encryption
    if pin is not None:
        iterations = compute_iteration_from_pin(pin, Nmin=Nmin, Nmax=Nmax)
    salt = random_bytearray(32)
    iv = random_bytearray(16)
    derive_key = create_derive_key(password, salt, iterations)
    ciphertext = encrypt_AES_CBC(data, derive_key, iv)
    expected_hmac = create_hmac(derive_key, iv, ciphertext)
    encryptedtext = create_encryptedtext(iv, salt, expected_hmac, ciphertext)
    # Deleting from memory all critical data for security
    delete_bytearray(data)
    delete_bytearray(password)
    if pin is not None:
        delete_bytearray(pin)
    delete_bytearray(derive_key)
    del iterations
    return False, 0, encryptedtext