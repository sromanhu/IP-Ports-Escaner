# IP-Ports-Escaner
Escáner de puertos abiertos sobre una IP

#!/bin/python3

#importados el módulo de nmap para poder usar sus funcionalidades#
import nmap

#Almacena la IP introducida por el usuario en spiderfot#
    host = eventData
	
#Lanza la función de nmap importada de escaner de puertos#
    nmapscan = nmap.PortScanner()
	    
#Con la función de escanear los puertos, le pasamos los datos de la IP del usuario y el rango de puertos a escanear#
    scan = nmapscan.scan(eventData, '1000-1005')
	    
#Muestra por pantalla el resultado del escaneado de puertos#
    print(scan)
