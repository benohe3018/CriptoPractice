from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

fichero_pub = "D:\\Ciberseguridad\\Modulo de Criptografía\\criptografia-main\\criptografia-main\\Practica\\clave-rsa-oaep-publ.pem"
fichero_priv = "D:\\Ciberseguridad\\Modulo de Criptografía\\criptografia-main\\criptografia-main\\Practica\\clave-rsa-oaep-priv.pem"

with open(fichero_pub, 'r') as f:
    keyPub = RSA.import_key(f.read())

# Cargar la clave privada
with open(fichero_priv, 'r') as fpriv:
    keyPriv = RSA.import_key(fpriv.read())

mensaje = bytes.fromhex('e2cff885901a5449e9c448ba5b948a8c4ee377152b3f1acfa0148fb3a426db72')

encryptor = PKCS1_OAEP.new(keyPub, SHA256)
encrypted = encryptor.encrypt(mensaje)

print("Mensaje encriptado: " + encrypted.hex())