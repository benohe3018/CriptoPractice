#XOR de datos binarios
#Creamos una función que recibe dos argumentos 
def xor_data(binary_data_1, binary_data_2):
    #Realizamos la operación XOR entre cada par de bytes que van a corresponder al binary_data_1 & binarydata_2
    #Dentro del bucle for combinamos a los elementos de los conjuntos de datos en pares con "zip" con "bytes" pasamos de números a bytes
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])
#convertimos a bytes desde el hexadecimal 
m = bytes.fromhex("B1EF2ACFE2BAEEFF")
k = bytes.fromhex("91BA13BA21AABB12")
#Imprimimos el valor que ha colocado el key manager llamando a la función xor_data, le pasamos los parametros en hexadecimal para que realice la operación
print("Valor que colocó el key manager: ",xor_data(m,k).hex())
#Asignamos los valores a un par de variables para buscar el valor con el que se trabajará en la memoria
num1=0xB1EF2ACFE2BAEEFF
num2=0xB98A15BA31AEBB3F
#Hacemos la operacion XOR entre las dos variables y la guardamos en una tercera en formato hexadecimal
num3=(hex(num1^num2))
#print(num3[2:])
#Imprimimos el resultado en pantalla, asignado a la variable 3.
print("Clave con la que se trabajará en memoria: ",num3)