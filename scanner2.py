import nmap

scanner = nmap.PortScanner()

print("seja bem vindo ao Scanner")
print("<----------------------->")

ip = input("Digite o Ip a ser varrido: ")
print("o ip digitado foi ", ip)

menu = input(""""\n Escolha o tipo de varredura:
                    1 -> Varredura SYN
                    2 -> Varredura UDP
                    3 -> Varredura Intensa
                    Digite a opção escolhida: """)

if menu == "1":
    print("O tipo escolhido foi: Varredura SYN")
    print("versão do Nmap: ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Status do IP: ", Scanner[ip].state())
    print(scanner[ip].all_protocols())
    print("")
    print("Portas abertas: ", scanner[ip]['tcp'].keys())
elif menu == "2":
    print("O tipo escolhido foi: Varredura UDP")
    print("versão do Nmap: ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Status do IP: ", Scanner[ip].state())
    print(scanner[ip].all_protocols())
    print("")
    print("Portas abertas: ", scanner[ip]['udp'].keys())
elif menu == "3":
    print("O tipo escolhido foi: Varredura Intensa")
    print("versão do Nmap: ", scanner.nmap_version())
    scanner.scan(ip, '1-1024', '-v -sC')
    print(scanner.scaninfo())
    print("Status do IP: ", scanner[ip].state())
    print(scanner[ip].all_protocols())
    print("")
    print("Portas abertas: ", scanner[ip]['tcp'].keys())
else:
    print("Escolha uma opção válida")
print("Varredura concluída. Obrigado por usar o Scanner!")