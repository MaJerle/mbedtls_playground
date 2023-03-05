import sys, random, base64, os, json
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

# Input string - make it 16 bytes aligned for future AES test
data_raw = 'This is my input data 0123456789'
data_raw_encoded = data_raw.encode('utf-8')

# Calculate SHA-256 hash option of it and get its digest
data_raw_hash = SHA256.new(data_raw_encoded)
data_raw_hash_digest = data_raw_hash.digest()

# Generate private/public key pair for ECC
# Use various formats for one curve -> PEM, compressed, uncompressed, ...
key = ECC.generate(curve = 'secp256r1')
private_key = key.export_key(format = 'PEM', compress = False) # Export private key
public_key = key.public_key().export_key(format = 'PEM', compress = False) # Generate public key and export it
public_key_sec1_compressed = key.public_key().export_key(format = 'SEC1', compress = True) # Generate public key and export it
public_key_sec1_uncompressed = key.public_key().export_key(format = 'SEC1', compress = False) # Generate public key and export it in uncompressed mode -> used by mbedTLS

# Sign the hash of raw data with private key
# Sign in P1363 format
print('Signature with P1363 format')
signer_p1363 = DSS.new(ECC.import_key(private_key), 'fips-186-3')
signature_p1363 = signer_p1363.sign(data_raw_hash)
print('signature _p1363', ''.join(['{:02X}'.format(i) for i in signature_p1363]))
print('len _p1363', len(signature_p1363))
# Sign in DER format - default for mbedTLS
print('Signature with DER format')
signer_der = DSS.new(ECC.import_key(private_key), 'fips-186-3', encoding = 'der')
signature_der = signer_der.sign(data_raw_hash)
print('signature _der', ''.join(['{:02X}'.format(i) for i in signature_der]))
print('len _der', len(signature_der))

# Quick signature verification
try:
    DSS.new(ECC.import_key(public_key), 'fips-186-3').verify(data_raw_hash, signature_p1363)
    print('Verification is OK - P1363')
except:
    print('Signature verification failed - P1363')
try:
    DSS.new(ECC.import_key(public_key), 'fips-186-3', encoding = 'der').verify(data_raw_hash, signature_der)
    print('Verification is OK - DER')
except:
    print('Signature verification failed - DER')

# Write generated data to files
with open('keys/data_raw_input_str.txt', 'w') as f:                 f.write(data_raw)
with open('keys/data_raw_input_array.txt', 'w') as f:               f.write(','.join([hex(i) for i in data_raw_encoded]))
with open('keys/data_raw_hash_digest_array.txt', 'w') as f:         f.write(','.join([hex(i) for i in data_raw_hash_digest]))
with open('keys/private.ec.key', 'w') as f:                         f.write(private_key)
with open('keys/public.ec.key', 'w') as f:                          f.write(public_key)
with open('keys/private.ec.oneline.key', 'w') as f:                 f.write('"' + str(private_key).replace('\n', '\\r\\n') + '"')
with open('keys/public.ec.oneline.key', 'w') as f:                  f.write('"' + str(public_key).replace('\n', '\\r\\n') + '"')
with open('keys/ecc_public_key_compressed_array.txt', 'w') as f:    f.write(','.join([hex(i) for i in public_key_sec1_compressed]))
with open('keys/ecc_public_key_uncompressed_array.txt', 'w') as f:  f.write(','.join([hex(i) for i in public_key_sec1_uncompressed]))
with open('keys/signature_der_array.txt', 'w') as f:                f.write(','.join([hex(i) for i in signature_der]))      # Signature of the hash
with open('keys/signature_p1363_array.txt', 'w') as f:              f.write(','.join([hex(i) for i in signature_p1363]))    # Signature of the hash

if True:
    # Generate random AES keys + IV - various length
    aes_iv_key = bytes([random.randint(0, 255) for _ in range(16)])
    aes128_key = bytes([random.randint(0, 255) for _ in range(16)])
    aes192_key = bytes([random.randint(0, 255) for _ in range(24)])
    aes256_key = bytes([random.randint(0, 255) for _ in range(32)])

    # Encrypt with all key sizes, then hash
    cipher_128 = AES.new(aes128_key, AES.MODE_CBC, iv = aes_iv_key)
    data_encrypted_aes128 = cipher_128.encrypt(data_raw_encoded)
    data_encrypted_aes128_hash_digest = SHA256.new(data_encrypted_aes128).digest()
    cipher_192 = AES.new(aes192_key, AES.MODE_CBC, iv = aes_iv_key)
    data_encrypted_aes192 = cipher_192.encrypt(data_raw_encoded)
    data_encrypted_aes192_hash_digest = SHA256.new(data_encrypted_aes192).digest()
    cipher_256 = AES.new(aes256_key, AES.MODE_CBC, iv = aes_iv_key)
    data_encrypted_aes256 = cipher_256.encrypt(data_raw_encoded)
    data_encrypted_aes256_hash_digest = SHA256.new(data_encrypted_aes256).digest()

    # Do decrypt
    cipher_128 = AES.new(aes128_key, AES.MODE_CBC, iv = aes_iv_key)
    data_decrypted_aes128 = cipher_128.decrypt(data_encrypted_aes128)
    cipher_192 = AES.new(aes192_key, AES.MODE_CBC, iv = aes_iv_key)
    data_decrypted_aes192 = cipher_192.decrypt(data_encrypted_aes192)
    cipher_256 = AES.new(aes256_key, AES.MODE_CBC, iv = aes_iv_key)
    data_decrypted_aes256 = cipher_256.decrypt(data_encrypted_aes256)

    # Write data to file
    with open('keys/aes_iv_array.txt', 'w') as f:                               f.write(','.join([hex(i) for i in aes_iv_key]))
    with open('keys/aes128_key_array.txt', 'w') as f:                           f.write(','.join([hex(i) for i in aes128_key]))
    with open('keys/aes192_key_array.txt', 'w') as f:                           f.write(','.join([hex(i) for i in aes192_key]))
    with open('keys/aes256_key_array.txt', 'w') as f:                           f.write(','.join([hex(i) for i in aes256_key]))
    with open('keys/data_encrypted_aes128_array.txt', 'w') as f:                f.write(','.join([hex(i) for i in data_encrypted_aes128]))
    with open('keys/data_encrypted_aes192_array.txt', 'w') as f:                f.write(','.join([hex(i) for i in data_encrypted_aes192]))
    with open('keys/data_encrypted_aes256_array.txt', 'w') as f:                f.write(','.join([hex(i) for i in data_encrypted_aes256]))
    with open('keys/data_encrypted_aes128_hash_digest_array.txt', 'w') as f:    f.write(','.join([hex(i) for i in data_encrypted_aes128_hash_digest]))
    with open('keys/data_encrypted_aes192_hash_digest_array.txt', 'w') as f:    f.write(','.join([hex(i) for i in data_encrypted_aes192_hash_digest]))
    with open('keys/data_encrypted_aes256_hash_digest_array.txt', 'w') as f:    f.write(','.join([hex(i) for i in data_encrypted_aes256_hash_digest]))

print('DONE')