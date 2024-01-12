import json
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
#Este importación nos permite trabajar con el programa keystore
import jks
import os

# Obteniendo el path
path = os.path.dirname(__file__)

keystore = path + "/Practica/KeyStorePracticas"

#Cargamos el keystore y le asignamos la contraseña que tiene actualmente
ks = jks.KeyStore.load(keystore, "123456")
#Vamos y buscamos la clave en el keystore iterando por todas las que estan almacenadas y hasta encontrar la que necesitamos
for alias, sk in ks.secret_keys.items():
    #Si el alias es igual a la clave que estamos buscando, la hemos encontrado
    if sk.alias == "cifrado-sim-aes-256":
        #Y se la asignamos a una variable para poder utilizarla posteriormente
        key = sk.key
#Imprimimos la clave en hexadecimal como mera información.
print("La clave es:", key.hex())

#Creamos una función para descifrar el mensaje, vamos a recibir como parametros el mensaje y la clave
def descifrar(mensaje_json, clave_bytes):
    
    #El mensaje lo cargaremos en formato json se asignará a la variable b64
    b64 = json.loads(mensaje_json)
    #Asignaremos nuestro vector de inicialización a la variable iv_bytes, lo pasaremos de base64 a bytes con 'decoded'
    iv_bytes = b64decode(b64['iv'])
    #Hacemos lo mismo con el texto cifrado
    texto_cifrado_bytes = b64decode(b64['texto cifrado'])
    #Creamos un nuevo objeto que será de tipo nuevo AES en modo CBC
    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    #Metemos todo a un bloque try and catch para el manejo de excepciones
    try:
        # Desciframos el texto cifrado y obtenemos los bytes del mensaje con padding
        mensaje_des_con_padding = cipher.decrypt(texto_cifrado_bytes)
        # Convertimos el mensaje con padding a una cadena hexadecimal para visualizarlo
        print("Mensaje cifrado en texto en claro (con padding):", mensaje_des_con_padding.hex())
        # Eliminamos el padding y lo convertimos a bytes, estilo pkcs7
        mensaje_des_bytes = unpad(mensaje_des_con_padding, AES.block_size, style="pkcs7")
        # Calculamos la longitud del padding
        padding_length = len(mensaje_des_con_padding) - len(mensaje_des_bytes)
        # Imprimimos los últimos bytes del mensaje (con padding)
        print("Últimos bytes del mensaje (con padding):", mensaje_des_con_padding[-padding_length:])
        # Devolvemos el mensaje descifrado y la longitud del padding
        return mensaje_des_bytes.decode("utf-8"), padding_length
    except (ValueError, KeyError) as error:
        return "Error en el descifrado: " + str(error), None


#Creamos el json con todos los datos necesarios para el descifrado y se lo asignamos a una variable unica
mensaje_cifrado_json = json.dumps({
    'iv': b64encode(bytes.fromhex('00000000000000000000000000000000')).decode('utf-8'),  # IV compuesto por ceros hexadecimales
    'texto cifrado': 'TQ9SOMKc6aFS9SlxhfK9wT18UXpPCd505Xf5J/5nLI7Of/o0QKIWXg3nu1RRz4QWElezdrLAD5LO4USt3aB/i50nvvJbBiG+le1ZhpR84oI='
})
# Luego, al usar la función, se puede obtener tanto el mensaje descifrado como la longitud del padding
texto_en_claro, padding_length = descifrar(mensaje_cifrado_json, key)
print(texto_en_claro)
if padding_length is not None:
    print("Cuanto padding tengo: ", padding_length, "byte(s)")
