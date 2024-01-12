from Crypto.Cipher import ChaCha20
from base64 import b64decode, b64encode
from Crypto.Hash import HMAC, SHA256
import base64
#Este importación nos permite trabajar con el programa keystore
import jks
import os
textoPlano_bytes = bytes('KeepCoding te enseña a codificar y a cifrar.', 'UTF-8')

#Importamos la clave desde el keystore para garantizar la confidencialidad y la integridad

# Obteniendo el path
path = os.path.dirname(__file__)

keystore = path + "/Practica/KeyStorePracticas"

#Cargamos el keystore y le asignamos la contraseña que tiene actualmente
ks = jks.KeyStore.load(keystore, "123456")
#Vamos y buscamos la clave en el keystore iterando por todas las que estan almacenadas y hasta encontrar la que necesitamos
for alias, sk in ks.secret_keys.items():
    #Si el alias es igual a la clave que estamos buscando, la hemos encontrado
    if sk.alias == "cifrado-sim-chacha20-256":
        #Y se la asignamos a una variable para poder utilizarla posteriormente
        key = sk.key

#Se requiere o 256 o 128 bits de clave, por ello usamos 256 bits que se transforman en 64 caracteres hexadecimales
clave = key
#convertimos directamente el nonce desde base64 a hexadecimal
b64_string= '9Yccn/f5nJJhAt2S'
decoded_bytes = base64.b64decode(b64_string)
hex_string = decoded_bytes.hex()
#Importante NUNCA debe fijarse el nonce, en este caso lo hacemos para mostrar el mismo resultado en cualquier lenguaje.
nonce_mensaje = hex_string


#Con la clave y con el nonce se cifra. El nonce debe ser único por mensaje
cipher = ChaCha20.new(key=clave, nonce=bytes.fromhex(nonce_mensaje))
texto_cifrado_bytes = cipher.encrypt(textoPlano_bytes)
#Mejoramos la integridad utilizando un HMAC
clave_hmac = key
hmac = HMAC.new(clave_hmac, digestmod=SHA256)
hmac.update(textoPlano_bytes)
hmac_digest =hmac.digest()
print('Mensaje cifrado en HEX = ', texto_cifrado_bytes.hex() )
print('Mensaje cifrado en B64 = ', b64encode(texto_cifrado_bytes).decode())
print('HMAC del mensaje cifrado: ', b64encode(hmac_digest).decode())