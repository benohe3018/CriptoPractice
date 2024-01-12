import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#Cifrado
texto_cifrado_bytes = bytes.fromhex("9f7bed764d3d98b582249abc04d13884ab59b5ff12d00c26a4143efe480463cfbd6c9031ca16a6b66429cc")
clave = bytes.fromhex('c936108299307d3f6f7585b96013346e')
nonce = bytes.fromhex('47e6831df094b7a7')

#Descifrado

try:

    tag_desc_bytes = bytes.fromhex("6621025a7877ce10cb35189df9af3c78")
    datos_asociados_desc_bytes = bytes("Hoy es miércoles", "UTF-8")
    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
    cipher.update(datos_asociados_desc_bytes)
    mensaje_des_bytes = cipher.decrypt_and_verify(texto_cifrado_bytes,tag_desc_bytes)
    print("El texto en claro es: ", mensaje_des_bytes.decode("utf-8"))

except (ValueError, KeyError) as error:
    print('Problemas para descifrar....')
    print("El motivo del error es: ", error) 