import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode


#Cifrado
textoPlano_bytes = bytes('He descubierto el error y no volveré a hacerlo mal', 'UTF-8')
clave = bytes.fromhex('E2CFF885901B3449E9C448BA5B948A8C4EE322152B3F1ACFA0148FB3A426DB74')
#Hacemos que nuestro nonce se genere de forma aleatoria.
nonce = get_random_bytes(12)

datos_asociados_bytes = bytes("Hoy es miércoles", "UTF-8")
cipher = AES.new(clave, AES.MODE_GCM,nonce=nonce)
#Esto es importante hacerlo en orden. 
cipher.update(datos_asociados_bytes)
#Vamos a cifrar y autenticar.
texto_cifrado_bytes, mac = cipher.encrypt_and_digest(textoPlano_bytes)

print("texto cifrado en hexadecimal: " + texto_cifrado_bytes.hex())
print("Texto cifrado en base 64: "+ b64encode(texto_cifrado_bytes).decode())
print("tag: " + mac.hex())