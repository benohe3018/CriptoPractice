from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

# Cargar tu clave privada (ajusta la ruta del archivo o carga la clave como una cadena)
fichero_pub = "D:\\Ciberseguridad\\Modulo de Criptografía\\criptografia-main\\criptografia-main\\Practica\\clave-rsa-oaep-publ.pem"
with open(fichero_pub, 'r') as fpub:
    keyPub = RSA.import_key(fpub.read())


# Mensaje que deseas firmar
message = bytes('El equipo está preparado para seguir con el proceso, necesitaremos más recursos.','utf8')

# Crear un hash del mensaje
h = SHA256.new(message)
signature = bytes.fromhex('a4606c518e0e2b443255e3626f3f23b77b9d5e1e4d6b3dcf90f7e118d6063950a23885c6dece92aa3d6eff2a72886b2552be969e11a4b7441bdeadc596c1b94e67a8f941ea998ef08b2cb3a925c959bcaae2ca9e6e60f95b989c709b9a0b90a0c69d9eaccd863bc924e70450ebbbb87369d721a9ec798fe66308e045417d0a56b86d84b305c555a0e766190d1ad0934a1befbbe031853277569f8383846d971d0daf05d023545d274f1bdd4b00e8954ba39dacc4a0875208f36d3c9207af096ea0f0d3baa752b48545a5d79cce0c2ebb6ff601d92978a33c1a8a707c1ae1470a09663acb6b9519391b61891bf5e06699aa0a0dbae21f0aaaa6f9b9d59f41928d')

# Mostrar la firma en hexadecimal
print("Firma en hexadecimal:", signature.hex())

verifier = PKCS115_SigScheme(keyPub)
try:
    verifier.verify(h, signature)
    print("Firma Valida.")
except:
    print("Firma Invalida.")