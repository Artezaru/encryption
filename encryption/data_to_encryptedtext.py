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
                          Nmax: int = 10_000_000,
                          delete_keys: bool = True
                          ) -> bytearray:
    """
    data_to_encryptedtext encrypts the data to generate the encrypted text.

    .. note::
        The data, password and pin will be deleted correctly in the function if no error occured.
        Otherwize, they need to be delete after dealing with Exception.

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
        delete_keys : bool
            Delete the data, the password and the pin correctly from memory at the end of the function.
            Default is True.

    Returns
    -------
        encryptedtext : bytearray
            The encrypted text. 

    Raises
    ------
        TypeError
            If a argument is wrong type.
        ValueError
            If iterations <= 0 or not (0 < Nmin < Nmax)
    """
    if (not isinstance(data, bytearray)) or (not isinstance(password, bytearray)) or ((pin is not None) and (not isinstance(pin, bytearray))):
        raise TypeError("Parameters data password or pin is not bytearray")
    if (pin is None) and (not isinstance(iterations, int)):
        raise TypeError("Parameter iterations is not integer")
    if (pin is None) and (iterations <= 0):
        raise ValueError("Parameter iterations is not positive integer")
    if (pin is not None) and (not (isinstance(Nmin, int) and isinstance(Nmax, int))):
        raise TypeError("Parameters Nmin and Nmax are not integer")
    if (pin is not None) and (not 0 < Nmin < Nmax):
        raise TypeError("Parameters Nmin and Nmax not respect 0 < Nmin < Nmax")
    if not isinstance(delete_keys, bool):
        raise ValueError("Parameter delete_keys is not a booleen.")
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
    if delete_keys:
        delete_bytearray(password)
        delete_bytearray(data)
        if pin is not None:
            delete_bytearray(pin)
    delete_bytearray(derive_key)
    del iterations
    return encryptedtext