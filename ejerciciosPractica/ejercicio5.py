import hashlib

#SHA_Keccap
# initiating the "s" object to use the
# sha3_256 algorithm from the hashlib module.
s = hashlib.sha3_256()

# will output the name of the hashing algorithm currently in use.
print(s.name)

# will output the Digest-Size of the hashing algorithm being used.
#print(s.digest_size)

# providing the input to the hashing algorithm.
s.update(bytes("En KeepCoding aprendemos cómo protegernos con criptografía","UTF-8"))

print('Sha Buscado: ', s.hexdigest())

m = hashlib.sha512()
m.update(bytes("En KeepCoding aprendemos cómo protegernos con criptografía", "utf8"))
print("SHA512: " + m.digest().hex())
print(m.digest_size)