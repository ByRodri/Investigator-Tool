import os
import platform
from colorama import *
from scapy.all import *
import socket
import requests

# Definición de funciones
def arp_scan(rangoip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rangoip)
    answered, unanswered = srp(arp_request, timeout=2, verbose=False)

    print("IP\t\t\t\tMAC Address")
    print("-----------------------------------------")
    for sent, received in answered:
        print(received.psrc + "\t\t" + received.hwsrc)

puertos_tcp = [21, 22, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162,
               179, 389, 427, 443, 465, 514, 520, 587, 636, 993, 995, 1194, 1701,
               1723, 3306, 3389, 8080]

puertos_udp = [21, 22, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162,
               179, 389, 427, 443, 465, 514, 520, 587, 636, 993, 995, 1194, 1701,
               1723, 3306, 3389, 8080]
puertos_escaneo = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,  3306, 3389, 8080]

def tcp_scan(ip_destino):
    while True:
        try:
            print(Fore.YELLOW + f"Realizando escaneo TCP Ping a la dirección IP: {ip_destino}..." + Style.RESET_ALL)
            dispositivos_responden = []
            for puerto in puertos_tcp:
                # Envía el paquete TCP SYN a cada puerto especificado
                tcp_result = sr(IP(dst=ip_destino) / TCP(dport=puerto, flags="S"), timeout=1, verbose=False)[0]
                if tcp_result:
                    print(f"El host responde al TCP ping en el puerto {puerto}")
                    dispositivos_responden.append(puerto)

            if dispositivos_responden:
                print(Fore.GREEN + f"El host responde en los puertos: {', '.join(map(str, dispositivos_responden))}" + Style.RESET_ALL)
            else:
                print(Fore.RED + "El host no responde en ninguno de los puertos TCP especificados" + Style.RESET_ALL)
            break
        except Exception as e:
            print("Error:", e)
            ip_destino = input("IP no válida. Intente nuevamente. Ingrese la dirección IP de destino: ")

def udp_ping(ip_destino):
    while True:
        try:
            print(Fore.YELLOW + f"Realizando escaneo UDP Ping a la dirección IP: {ip_destino}..." + Style.RESET_ALL)
            dispositivos_responden = []
            for puerto in puertos_udp:
                # Envía el paquete UDP a cada puerto especificado
                udp_result = sr(IP(dst=ip_destino) / UDP(dport=puerto), timeout=1, verbose=False)[0]
                if udp_result:
                    print(f"El host responde al UDP ping en el puerto {puerto}")
                    dispositivos_responden.append(puerto)

            if dispositivos_responden:
                print(Fore.GREEN + f"El host responde en los puertos: {', '.join(map(str, dispositivos_responden))}" + Style.RESET_ALL)
            else:
                print(Fore.RED + "El host no responde en ninguno de los puertos UDP especificados" + Style.RESET_ALL)
            break
        except Exception as e:
            print("Error:", e)
            ip_destino = input("IP no válida. Intente nuevamente. Ingrese la dirección IP de destino: ")

def icmp_ping(ip_destino):
    try:
        print(Fore.YELLOW + f"Enviando ICMP Ping a la dirección IP: {ip_destino}..." + Style.RESET_ALL)
        icmp_result = sr1(IP(dst=ip_destino) / ICMP(), timeout=1, verbose=False)
        if icmp_result:
            print(Fore.GREEN + "Host activo: Respuesta recibida!" + Style.RESET_ALL)
        else:
            print(Fore.RED + "El host no respondió al ICMP Ping" + Style.RESET_ALL)
    except Exception as e:
        print("Error:", e)

def enum_ports(ip_destino, puertos):
    print(f"Iniciando enumeración de puertos en {ip_destino}...")
    puertos_abiertos = []
    for puerto in puertos_escaneo:
        syn_ack_pkt = sr1(IP(dst=ip_destino) / TCP(dport=puerto, flags="S"), timeout=1, verbose=False)
        if syn_ack_pkt and syn_ack_pkt.haslayer(TCP) and syn_ack_pkt[TCP].flags == 0x12:  # SYN-ACK
            print(f"Puerto {puerto}: Abierto")
            puertos_abiertos.append(puerto)
        else:
            print(f"Puerto {puerto}: Cerrado")
    return puertos_abiertos

def ack_scan(ip_destino, puerto_destino):
    print(Fore.YELLOW + f"Iniciando escaneo de tipo ACK Scan en {ip_destino}:{puerto_destino}..." + Style.RESET_ALL)
    respuesta = sr1(IP(dst=ip_destino) / TCP(dport=puerto_destino, flags="A"), timeout=1, verbose=False)

    if respuesta:
        if respuesta.haslayer(TCP) and respuesta[TCP].flags == 0x4:  # Respuesta RST
            print(Fore.RED + f"Puerto {puerto_destino}: Cerrado" + Style.RESET_ALL)
        elif respuesta.haslayer(ICMP) and int(respuesta[ICMP].type) == 3 and int(respuesta[ICMP].code) in [1, 2, 3, 9, 10, 13]:  # Respuesta ICMP "Administratively Prohibited"
            print(Fore.CYAN + f"Puerto {puerto_destino}: Filtrado" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"Puerto {puerto_destino}: Abierto o filtrado" + Style.RESET_ALL)
    else:
        print(Fore.RED + f"No se recibió respuesta del puerto {puerto_destino}" + Style.RESET_ALL)

def bannergrabbing(ip, port):
    try:
        # Crear un socket TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Conectar al puerto especificado de la IP objetivo
        s.connect((ip, port))
        
        # Enviar una solicitud HTTP simple si es el puerto 80 o 443 (HTTP/HTTPS)
        if port == 80 or port == 443:
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + bytes(ip, 'utf-8') + b"\r\n\r\n")
        else:
            s.sendall(b'Hello\r\n')
        
        # Recibir la respuesta
        response = s.recv(1024)
        # Imprimir el banner (respuesta del servidor)
        print(response.decode('utf-8', errors='ignore'))
        
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)

    finally:
        s.close()

def evaluate_http_headers(ip_or_domain):
    try:
        # Resolver el dominio a IP si se proporciona un dominio
        ip = socket.gethostbyname(ip_or_domain)
        print(Fore.WHITE + f"----------------RESULTADO----------------" + Style.RESET_ALL)
        print(Fore.GREEN +  f"Resolucion de la IP: {ip}" + Style.RESET_ALL)
    except socket.gaierror:
        print(Fore.RED + f"Error!! IP o dominio invalido, revisalo!: {ip_or_domain}" + Style.RESET_ALL)
        return
    
    # Preparar la URL
    url = f"http://{ip}"
    
    try:
        # Hacer la solicitud HTTP
        response = requests.get(url)
        
        # Imprimir el código de estado y las cabeceras
        print(f"HTTP Status Code: {response.status_code}")
        print("HTTP Headers:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    
    except requests.RequestException as e:
        print(f"HTTP request failed: {e}")

def detect_os_by_ttl(ip_destino):
    try:
        print(Fore.MAGENTA + f"Enviando ping a la dirección IP: {ip_destino}..." + Style.RESET_ALL)
        icmp_result = sr1(IP(dst=ip_destino) / ICMP(), timeout=1, verbose=False)
        
        if icmp_result:
            ttl = icmp_result[IP].ttl
            print(Fore.GREEN + f"TTL recibido: {ttl}" + Style.RESET_ALL)
            
            if ttl <= 64:
                print(Fore.GREEN + "El sistema operativo probable es Linux/Unix" + Style.RESET_ALL)
            elif ttl <= 128:
                print(Fore.GREEN + "El sistema operativo probable es Windows" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "El sistema operativo probable es desconocido" + Style.RESET_ALL)
        else:
            print(Fore.RED + "No se recibió respuesta al ping" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)


# Definición de funcionamiento menús
def descubrimiento_maquinas():
    while True:
        print("\nSeleccione una técnica de descubrimiento de máquinas:")
        print("1. ARP Ping")
        print("2. TCP Ping")
        print("3. UDP Ping")
        print("4. ICMP Ping")
        print("5. Volver al menú principal")

        opcion = input("Ingrese su opción: ")
        if opcion == "1":
            print("Ha seleccionado ARP Ping")
            rangopregunta = input("Que rango de IP quieres escanear (Ej: 192.168.1.0/24): ")
            arp_scan(rangopregunta)
        elif opcion == "2":
            print("Ha seleccionado TCP Ping")
            ip_destino = input("Ingrese la dirección IP de destino: ")
            tcp_scan(ip_destino)
        elif opcion == "3":
            print("Ha seleccionado UDP Ping")
            ip_destino = input("Ingrese la dirección IP de destino: ")
            udp_ping(ip_destino)
        elif opcion == "4":
            print("Ha seleccionado ICMP Ping")
            ip_destino = input("Ingrese la dirección IP de destino: ")
            icmp_ping(ip_destino)
        elif opcion == "5":
            break
        else:
            print(Fore.RED + "Opción no válida. Inténtalo de nuevo." + Style.RESET_ALL)

def enumeracion_puertos():
    while True:
        print("\nSeleccione un método de enumeración de puertos:")
        print("1. Escaneo")
        print("2. Volver al menú principal")

        opcion = input("Ingrese su opción: ")
        if opcion == "1":
            print("Ha seleccionado escaneo")
            ip_destino = input("Ingrese la dirección IP de destino: ")
            puertos_abiertos = enum_ports(ip_destino, puertos_escaneo)
            print(Fore.GREEN + "+----------------------------------------------+" + Style.RESET_ALL)
            print(Fore.GREEN + "Puertos abiertos:" + Style.RESET_ALL, Fore.GREEN + str(puertos_abiertos) + Style.RESET_ALL)
            print(Fore.GREEN + "+----------------------------------------------+" + Style.RESET_ALL)
        elif opcion == "2":
            break
        else:
            print(Fore.RED + "Opción no válida. Inténtalo de nuevo." + Style.RESET_ALL)

def detecion_firewalls():
    ip_destino = input("Ingrese la dirección IP de destino: ")
    puerto_destino = int(input("Ingrese el puerto de destino: "))
    print(Fore.GREEN + "+----------------------------------------------+" + Style.RESET_ALL)
    ack_scan(ip_destino, puerto_destino)
    print(Fore.GREEN + "+----------------------------------------------+" + Style.RESET_ALL)

def banner_grabbing():
    while True:
        print("\nSeleccione un método de banner grabbing:")
        print("1. Banner Grabbing")
        print("2. Volver al menú principal")

        opcion = input("Ingrese su opción: ")
        if opcion == "1":
            print(Fore.GREEN + "+----------------------------------------------+" + Style.RESET_ALL)
            ip = input("Introduce la IP objetivo: ")
            print(Fore.GREEN + "+----------------------------------------------+" + Style.RESET_ALL)
            port = int(input("Introduce el puerto objetivo: "))
            print(Fore.GREEN + "+----------------------------------------------+" + Style.RESET_ALL)
            print(Fore.YELLOW + "+-------------------RESULTADO BANNER GRABBING---------------------+" + Style.RESET_ALL)
            bannergrabbing(ip, port)
        elif opcion == "2":
            break
        else:
            print(Fore.RED + "Opción no válida. Inténtalo de nuevo." + Style.RESET_ALL)

def evaluacion_cabeceras_http():
    while True:
        print("\nSelecciona una técnica de evaluación de cabeceras HTTP:")
        print("1. Evaluacion de cabeceras HTTP")
        print("2. Volver al menú principal")

        opcion = input("Ingrese su opción: ")
        if opcion == "1":
            print("Ha selecccionado evaluacion de cabeceras HTTP")
            ip_or_domain = input(Fore.BLUE + "Introduce la IP o dominio objetivo: " + Style.RESET_ALL)
            evaluate_http_headers(ip_or_domain)
        elif opcion == "2":
            break
        else:
            print(Fore.RED + "Opción no válida. Inténtalo de nuevo." + Style.RESET_ALL)

def deteccion_sistemas_operativos():
    while True:
        print("\nSelecciona una técnica de deteccion de SO:")
        print("1. Deteccion de SO por TTL")
        print("2. Volver al menú principal")

        opcion = input("Ingrese su opción: ")
        if opcion == "1":
            print("Ha selecccionado Deteccion de SO por TTL")
            ip_destino = input("Introduce la IP objetivo: ")
            detect_os_by_ttl(ip_destino)
        elif opcion == "2":
            break
        else:
            print("Opción no válida. Inténtalo de nuevo.")

def mostrar_menu():
    print('''\
                                           *@#                               
                                  (@@@@@@@@@@@@%@@                             
                                 @@@@@@@@@@@@@@%@@&                            
                                 @             ,  @                            
                              @@@@@@@@@@@@@@@@@@@@@@                            
                            @@@@@@@@@ @@@@@@@@@@@@@@@@@@                        
                               , @@ , .@  @@@@@/#@@@@@@&  *@@@@%               
                                  @@              @      /@@@  @/@              
                             .    ,@   ,          @@@     @@@,  *@%               
                            .@@@  @    @       @       @@@   @@&                
                     .@@@@@@@@@@   .@   @@@@@@@@.     @@@   @ @                 
                  @@@&@@@@@@@@@@@    @@@   .@@@@%@@@@ @@@ @ @                   
                @@@@@&@@@@@@@@@@@@ @.@@@@. @@@@@%@@@@@@ @                       
               @@@@@@&@@@@@@@@@@@@@  @@@  #@@@@@,       @@                      
              @@@@@@@&@@@@@@@@@@@@@#@@@@ @@@@   ,      @ @@                     
              @@@@@@@@@@@@@@@@@@@@@@@@@@@@            @@@@@(                    
              @@@@@@@@@@@@@@@@@@@@@@@@@  @.   @@&@@  @@@@@@@                    
              @@@@@@@@@@@@@@@@@@%@@@@&@@   @@@@@@@@@@@@@@@@@
              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 
''')
    print(Fore.RED + "Bienvenido a Investigator! ¿Que deseas analizar?" + Style.RESET_ALL)
    print("Seleccione una opción:")
    print("1. Descubrimiento de Máquinas")
    print("2. Enumeración de Puertos")
    print("3. Detecion de Firewalls")
    print("4. Banner Grabbing")
    print("5. Evaluacion de cabeceras")
    print("6. Deteccion de sistemas operativos")
    print("7. Salir")

# Menú de la herramienta
while True:
    mostrar_menu()
    opcion = input("Ingrese su opción: ")

    if opcion == "1":
        descubrimiento_maquinas()
    elif opcion == "2":
        enumeracion_puertos()
    elif opcion == "3":
        detecion_firewalls()
    elif opcion == "4":
        banner_grabbing()
    elif opcion == "5":
        evaluacion_cabeceras_http()
    elif opcion == "6":
        deteccion_sistemas_operativos()
    # Agrega la lógica para las otras opciones del menú principal
    elif opcion == "7":
        print("Saliendo...")
        break
    else:
        print(Fore.RED + "Opción no válida. Inténtalo de nuevo." + Style.RESET_ALL)