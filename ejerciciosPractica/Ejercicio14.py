from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
import os
import jks

#Vamos a declarar la ruta desde donde vamos a extraer la clave maestra
path = os.path.dirname(__file__)
keystore = "D:\Ciberseguridad\Modulo de Criptografía\criptografia-main\criptografia-main\codigo fuente\Hashing y Authentication\Practica\KeyStorePracticas"

#Asignamos a una variable la carga del archivo con la respectiva contraseña que lo limita
ks = jks.KeyStore.load(keystore, "123456")
for alias, sk in ks.secret_keys.items():
    if sk.alias == "cifrado-sim-aes-256":
        key =sk.key
print("La clave maestra es: ", key.hex())


#Asignamos la clave maestra a una variable 
master_key = key
#Asignamos al SALT el icentificador del dispositivo
salt = bytes.fromhex("e43bb4067cbcfab3bec54437b84bef4623e345682d89de9948fbb0afedc461a3")
#Generamos la clave diversificada recibiendo como parámetros la clave maestra, 32 bits, el salt con la ID del dispositivo(Valor hexadecimal), el Hashing a 512
clave_diversificada = HKDF(master_key, 32, salt, SHA512, 1)
print("Clave obtenida: ", clave_diversificada.hex())
