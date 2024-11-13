from typing import Optional
from .compute_iteration_from_pin import compute_iteration_from_pin
from .create_derive_key import create_derive_key
from .delete_bytearray import delete_bytearray
from .extract_cryptography_components import extract_cryptography_components
from .verify_key import verify_key
from .decrypt_AES_CBC import decrypt_AES_CBC
from .wrong_key_error import WrongKeyError

def encryptedtext_to_data(encryptedtext: bytearray, password: bytearray, *, 
                          pin: Optional[bytearray] = None, 
                          iterations: int = 100_000,
                          Nmin: int = 100_000,
                          Nmax: int = 10_000_000
                          ) -> bytearray:
    """
    encryptedtext_to_data decrypts the encrypted text to generate the data.

    .. note::
        password and pin will be deleted correctly in the function if no error occured.
        Otherwize, they need to be delete after dealing with Exception.

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
        data : bytearray
            The decrypting message using AES in CBC mode.
    
    Raises
    ------
        TypeError
            If a argument is wrong type.
        ValueError
            If iterations <= 0 or not (0 < Nmin < Nmax)
            If encryptedtext is not at least 80 bytes long 
        WrongKeyError
            If the password or the pin is incorect.
            If the encryptedtext has been modified.
    """
    if (not isinstance(encryptedtext, bytearray)) or (not isinstance(password, bytearray)) or ((pin is not None) and (not isinstance(pin, bytearray))):
        raise TypeError("Parameters encryptedtext password or pin is not bytearray")
    if (pin is None) and (not isinstance(iterations, int)):
        raise TypeError("Parameter iterations is not integer")
    if (pin is None) and (iterations <= 0):
        raise ValueError("Parameter iterations is not positive integer")
    if (pin is not None) and (not (isinstance(Nmin, int) and isinstance(Nmax, int))):
        raise TypeError("Parameters Nmin and Nmax are not integer")
    if (pin is not None) and (not 0 < Nmin < Nmax):
        raise TypeError("Parameters Nmin and Nmax not respect 0 < Nmin < Nmax")
    if len(encryptedtext) < 80:
        raise ValueError("Parameter encryptedtext is not at least 80 bytes long.")
    # Encryption
    if pin is not None:
        iterations = compute_iteration_from_pin(pin, Nmin=Nmin, Nmax=Nmax)
    iv, salt, expected_hmac, ciphertext = extract_cryptography_components(encryptedtext)
    derive_key = create_derive_key(password, salt, iterations)
    if not verify_key(derive_key, iv, ciphertext, expected_hmac):
        raise WrongKeyError("WARNING : password and pin can't decrypt the encryptedtext")
    data = decrypt_AES_CBC(ciphertext, derive_key, iv)
    # Deleting from memory all critical data for security
    delete_bytearray(password)
    delete_bytearray(pin)
    delete_bytearray(derive_key)
    del iterations
    return data