# encryption

## Description
AES-CBC encryption tools.

Use encryption to encrypt data into encryptedtext with user password.

## Author
- Name: Artezaru
- Email: artezaru.github@proton.me
- GitHub: [Artezaru](https://github.com/Artezaru/encryption.git)

## Installation

Install with pip

```
pip install git+https://github.com/Artezaru/encryption.git
```

Clone with git

```
git clone https://github.com/Artezaru/encryption.git
```

## Documentation

Generate the documentation with sphinx

```
make html
```

## Example

``` python
from encryption import *

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
```

## License
See LICENSE
