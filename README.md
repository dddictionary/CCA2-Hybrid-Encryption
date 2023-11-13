# CSC38000 Computer Security

## CCA2 Encryption:

> Build a public key cryptosystem using a key encapsulation mechanism (KEM)

- Assymetric System:
        - RSA
            - using GMP to operate with arbitrary precision numbers 
    - build symmetric system denoted as SKE
        - SKE that works only on buffers
        - SKE that works on files
        - SKE
            - Encryption:
                - 16 byte IV | C = AES(plaintext) | 32byte SHA256 HMAC(C)
                - IV = initialization vectors, unpredictable random number to make sure that when same message is encrypted more than once, the ciphertext is different 
            - Decryption:
                1. Check hmac of iv + c
                2. Decrypt ciphertext 
    - KEM:
        - combine RSA and SKE on files
        - ciphertext will be:
            - RSA-KEM(x) | SKE ciphertext
            - Generate SKE key with x, where x has as much entropy as the key

## Members
- [Joshua Henry](https://github.com/jhenrynyc)
- [Abrar Habib](https://github.com/dddictionary)
