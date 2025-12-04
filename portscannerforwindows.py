###########################################################
# Leonardo Reis                                           #
# https://www.linkedin.com/in/leonardo-reis-31ba3415b/    #
###########################################################

import tkinter as tk
import tkinter.ttk as ttk
import socket
import requests
from tkinter.filedialog import askopenfilename
import ipaddress

def get_host_info():
    host = entry_host.get()
    
    try:
        response = requests.get(f"https://ipinfo.io/{host}/json")
        data = response.json()

        result_text = f"Host: {data['ip']}\n"
        result_text += f"Cidade: {data.get('city', 'N/A')}\n"
        result_text += f"Região: {data.get('region', 'N/A')}\n"
        result_text += f"País: {data.get('country', 'N/A')}\n"
        result_text += f"Provedor: {data.get('org', 'N/A')}\n"

        result.delete('1.0', tk.END)
        result.insert(tk.END, result_text)
    except Exception as e:
        result.delete('1.0', tk.END)
        result.insert(tk.END, f"Erro ao obter informações do host: {e}")

def check_port():
    host = entry_host2.get()
    port = entry_port2.get()

    result2.delete('1.0', tk.END)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if sock.connect_ex((host, int(port))) == 0:
            result_text = f"A porta {port} está aberta para o host {host}"
        else:
            result_text = f"A porta {port} está fechada para o host {host}"

        result2.insert(tk.END, result_text)
    except Exception as e:
        result2.insert(tk.END, f"Erro ao verificar a porta: {e}")

def load_ip_file():
    filename = askopenfilename(filetypes=[("Text Files", "*.txt")])
    
    if not filename:
        return
    
    with open(filename, 'r') as file:
        ips = file.readlines()

    rules = []
    block_list = "BlockedRanges"
    for ip in ips:
        ip = ip.strip()
        try:
            if '/' in ip:
                network = ipaddress.ip_network(ip, strict=False)
            else:
                network = ipaddress.ip_network(f"{ip}/32", strict=False)
            
            rule = f"/ip firewall address-list add list={block_list} address={network}"
            rules.append(rule)
        except ValueError as e:
            print(f"Erro ao processar o IP {ip}: {e}")
    
    filter_rule = f"/ip firewall filter add action=drop chain=input src-address-list={block_list} comment=\"Block traffic from specific IP ranges\""

    result3.delete('1.0', tk.END)
    result3.insert(tk.END, "\n".join(rules) + "\n" + filter_rule)

window = tk.Tk()
window.title("O caçador v.3.0 Hacking Alchemy")
window.geometry("900x700")
window.configure(bg="#111111")

style = ttk.Style()
style.configure("TNotebook", background="#2d2d2d", tabmargins=[1, 5, 1, 0], relief="flat")
style.configure("TNotebook.Tab", background="#333333", foreground="#333333", font=("Courier New", 12, "bold"), padding=[10, 5])
style.map("TNotebook.Tab", background=[('selected', '#555555')])

style.configure("TFrame", background="#2d2d2d")
style.configure("TButton", background="#33FF00", foreground="#000000", font=("Courier New", 14), relief="flat")
style.configure("TText", background="#222222", foreground="#33FF00", font=("Courier New", 12), relief="flat")

notebook = ttk.Notebook(window)
info_frame = ttk.Frame(notebook, style="TFrame")
notebook.add(info_frame, text="Informações do Host")
ports_frame = ttk.Frame(notebook, style="TFrame")
notebook.add(ports_frame, text="Verificar Portas (Externo)")
ip_block_frame = ttk.Frame(notebook, style="TFrame")
notebook.add(ip_block_frame, text="Carregar IPs e Criar Regras")

style.configure("TNotebook.Tab", font=("Courier New", 12, "bold"))

notebook.grid(row=0, column=0, padx=20, pady=20)

host_label = tk.Label(info_frame, text="Host:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
host_label.grid(row=0, column=0, padx=10, pady=10)

entry_host = tk.Entry(info_frame, font=("Courier New", 14), width=30, relief="flat", bg="#222222", fg="#FFFFFF")
entry_host.grid(row=0, column=1, padx=10, pady=10)

info_button = tk.Button(info_frame, text="Obter Informações", command=get_host_info)
info_button.grid(row=1, column=0, columnspan=2, padx=10, pady=15)

result = tk.Text(info_frame, height=10, width=40)
result.grid(row=2, column=0, columnspan=2, padx=20, pady=10)

host_label2 = tk.Label(ports_frame, text="Host:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
host_label2.grid(row=0, column=0, padx=10, pady=10)

entry_host2 = tk.Entry(ports_frame, font=("Courier New", 14), width=30, relief="flat", bg="#222222", fg="#FFFFFF")
entry_host2.grid(row=0, column=1, padx=10, pady=10)

port_label2 = tk.Label(ports_frame, text="Porta:", font=("Courier New", 14), fg="#33FF00", bg="#2d2d2d")
port_label2.grid(row=1, column=0, padx=10, pady=10)

entry_port2 = tk.Entry(ports_frame, font=("Courier New", 14), width=10, relief="flat", bg="#222222", fg="#FFFFFF")
entry_port2.grid(row=1, column=1, padx=10, pady=10)

check_button = tk.Button(ports_frame, text="Verificar", command=check_port)
check_button.grid(row=2, column=0, columnspan=2, padx=10, pady=15)

result2 = tk.Text(ports_frame, height=10, width=40)
result2.grid(row=3, column=0, columnspan=2, padx=20, pady=10)

load_button = tk.Button(ip_block_frame, text="Carregar Arquivo de IPs", command=load_ip_file)
load_button.grid(row=0, column=0, padx=10, pady=20)

result3 = tk.Text(ip_block_frame, height=10, width=40)
result3.grid(row=1, column=0, padx=20, pady=10)

footer = tk.Label(window, text="Desenvolvido por Hacking Alchemy", font=("Courier New", 10), fg="#888888", bg="#111111")
footer.grid(row=1, column=0, pady=10)

window.mainloop()
