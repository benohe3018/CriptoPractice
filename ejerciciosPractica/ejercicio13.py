from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

# Cargar tu clave privada (ajusta la ruta del archivo o carga la clave como una cadena)
fichero_priv = "D:\\Ciberseguridad\\Modulo de Criptografía\\criptografia-main\\criptografia-main\\Practica\\clave-rsa-oaep-priv.pem"
with open(fichero_priv, 'r') as fpriv:
    keyPriv = RSA.import_key(fpriv.read())


# Mensaje que deseas firmar
message = bytes('El equipo está preparado para seguir con el proceso, necesitaremos más recursos.','utf8')

# Crear un hash del mensaje
h = SHA256.new(message)
signer = PKCS115_SigScheme(keyPriv)
signature = signer.sign(h)

# Mostrar la firma en hexadecimal
print("Firma en hexadecimal:", signature.hex())
