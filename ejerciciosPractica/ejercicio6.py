from Crypto.Hash import HMAC, SHA256
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
    if sk.alias == "hmac-sha256":
        #Y se la asignamos a una variable para poder utilizarla posteriormente
        key = sk.key

#Generamos el hmac, en este caso SHA256 - HMAC-256
clave = key
mensaje_bytes_con_punto = bytes("Siempre existe más de una forma de hacerlo, y más de una solución válida.","utf8")
hmac256_con_punto = HMAC.new(clave,mensaje_bytes_con_punto,digestmod=SHA256)
#Propio de los hmac, como representar el valor
print('HMAC generado: ',hmac256_con_punto.hexdigest())
