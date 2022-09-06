#!/usr/bin/env python3

from Crypto.PublicKey import RSA


private_key = RSA.generate(1024)
public_key = private_key.publickey()

for key, val in {'private_key':private_key, 'public_key':public_key}.items():
  key_pem = val.export_key().decode()
  with open(f'{key}.pem', 'w') as f:
    f.write(key_pem)
