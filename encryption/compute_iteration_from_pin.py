def compute_iteration_from_pin(pin: bytearray, Nmin: int = 100_000, Nmax: int = 10_000_000) -> int:
    """
    Compute the number of iterations for PBKDF2 with the user PIN. 

    Parameters
    ----------
        pin : bytearray
            The user pin.
        Nmin : int
            The minimum number of iteration to return. 
            Default is 100_000.
        Nmin : int
            The maximum number of iteration to return.
            Default is 10_000_000.

    Returns
    -------
        iterations : int
            The number of iterations to use for PBKDF2.

    Raises
    ------
        TypeError
            If a given argument is wrong type.
        ValueError
            If empty pin or `Nmin` and `Nmax` are not positive integers of `Nmin` >= `Nmax`.
    """
    if not isinstance(pin, bytearray):
        raise TypeError('Parameter pin is not bytearray instance.')
    if not isinstance(Nmin, int):
        raise TypeError('Parameter Nmin is not int instance.')
    if not isinstance(Nmax, int):
        raise TypeError('Parameter Nmax is not int instance.')
    if len(pin) == 0:
        raise ValueError('Parameter pin must not be empty.')
    if not 0 < Nmin < Nmax :
        raise ValueErrbytes(pin, byteorder='big')

    number = int.from_bytes(pin, byteorder='big')
    iterations = Nmin + number%(Nmax - Nmin + 1) # Applying modulo to get a number between 0 and Nmax-Nmin
    return  iterations