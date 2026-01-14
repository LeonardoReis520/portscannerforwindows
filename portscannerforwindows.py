
###########################################################
# Leonardo Reis                                           #
# https://www.linkedin.com/in/leonardo-reis-31ba3415b/    #
###########################################################

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import scrolledtext
from tkinter.filedialog import askopenfilename, asksaveasfilename
import socket
import ssl
import requests
import ipaddress
import threading
import time
import csv
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor

APP_TITLE = "Oxossi SOC v4.0 - Leonardo Reis"
APP_SIZE = "1080x780"

COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1900: "SSDP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8000: "Alt-HTTP",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9000: "SonarQube/Alt",
    9200: "Elasticsearch",
    11211: "Memcached"
}

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def safe_insert_text(text_widget, content):
    text_widget.configure(state='normal')
    text_widget.delete('1.0', tk.END)
    text_widget.insert(tk.END, content)
    text_widget.configure(state='disabled')

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_host(host):
    """Resolve host to IP (v4/v6). Returns (ip, family)."""
    try:
        infos = socket.getaddrinfo(host, None)
        # Prefer IPv4 for readability
        for info in infos:
            family, _, _, _, sockaddr = info
            if family == socket.AF_INET:
                return sockaddr[0], family
        # Fallback to IPv6
        family, _, _, _, sockaddr = infos[0]
        return sockaddr[0], family
    except Exception as e:
        raise RuntimeError(f"Falha ao resolver host '{host}': {e}")

def whois_query(domain):
    """Minimal WHOIS via port 43: ask IANA for referral server and query it."""
    try:
        # Ask IANA for referral
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(6)
            s.connect(("whois.iana.org", 43))
            s.sendall((domain + "\r\n").encode("utf-8"))
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        text = data.decode(errors="ignore")
        whois_server = None
        for line in text.splitlines():
            if line.lower().startswith("refer:"):
                whois_server = line.split(":", 1)[1].strip()
                break
        # Fallback servers for common TLDs
        if not whois_server:
            if domain.endswith(".com") or domain.endswith(".net"):
                whois_server = "whois.verisign-grs.com"
            elif domain.endswith(".org"):
                whois_server = "whois.pir.org"
            else:
                whois_server = "whois.iana.org"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.settimeout(8)
            s2.connect((whois_server, 43))
            s2.sendall((domain + "\r\n").encode("utf-8"))
            data2 = b""
            while True:
                chunk = s2.recv(4096)
                if not chunk:
                    break
                data2 += chunk
        return f"Servidor WHOIS: {whois_server}\n\n" + data2.decode(errors="ignore")
    except Exception as e:
        return f"Erro WHOIS para '{domain}': {e}"

def tcp_check(host, port, timeout=1.5):
    """Return True if TCP port open, False otherwise."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, int(port))) == 0
    except Exception:
        return False

def https_certificate_info(host, port=443, timeout=6):
    """Return TLS certificate subject/issuer/validity for HTTPS endpoint."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # Extract basic fields
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        not_before = cert.get('notBefore', 'N/A')
        not_after = cert.get('notAfter', 'N/A')
        san = cert.get('subjectAltName', [])
        san_dns = [x[1] for x in san if x[0] == 'DNS']
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "san_dns": san_dns
        }
    except Exception as e:
        return {"error": str(e)}

class SOCApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(APP_SIZE)
        self.configure(bg="#111111")
        self.minsize(980, 700)

        self.ipinfo_token = tk.StringVar(value="")  # opcional
        self.status_var = tk.StringVar(value="Pronto.")
        self._build_style()
        self._build_layout()

    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Dark palette
        bg = "#1e1e1e"
        fg = "#d0d0d0"
        acc = "#33FF00"
        style.configure(".", background=bg, foreground=fg, fieldbackground="#222222")
        style.configure("TNotebook", background=bg)
        style.configure("TNotebook.Tab", background="#2a2a2a", foreground="#cfcfcf", font=("Consolas", 12, "bold"), padding=(14, 8))
        style.map("TNotebook.Tab", background=[('selected', '#3a3a3a')], foreground=[('selected', '#ffffff')])

        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, foreground="#9ad88f", borderwidth=1)
        style.configure("TLabelframe.Label", background=bg, foreground="#9ad88f", font=("Consolas", 12, "bold"))
        style.configure("TLabel", background=bg, foreground=fg, font=("Consolas", 11))
        style.configure("TEntry", fieldbackground="#222222", foreground="#ffffff", insertcolor="#ffffff")
        style.configure("TButton", background=acc, foreground="#000000", font=("Consolas", 12, "bold"), padding=8)
        style.map("TButton", background=[('active', '#5fff2a')])
        style.configure("Treeview", background="#232323", fieldbackground="#232323", foreground="#eaeaea", rowheight=26)
        style.configure("Horizontal.TProgressbar", background=acc)

    def _build_layout(self):
        # Notebook
        self.nb = ttk.Notebook(self)
        self.nb.grid(row=0, column=0, sticky="nsew", padx=16, pady=12)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Tabs
        self.tab_info = ttk.Frame(self.nb)
        self.tab_port_single = ttk.Frame(self.nb)
        self.tab_port_range = ttk.Frame(self.nb)
        self.tab_http = ttk.Frame(self.nb)
        self.tab_firewall = ttk.Frame(self.nb)
        self.tab_utils = ttk.Frame(self.nb)

        self.nb.add(self.tab_info, text="Informações do Host")
        self.nb.add(self.tab_port_single, text="Porta Única")
        self.nb.add(self.tab_port_range, text="Scanner de Portas (Intervalo)")
        self.nb.add(self.tab_http, text="HTTP/HTTPS")
        self.nb.add(self.tab_firewall, text="Regras de Firewall")
        self.nb.add(self.tab_utils, text="Utilitários")

        self._build_info_tab()
        self._build_port_single_tab()
        self._build_port_range_tab()
        self._build_http_tab()
        self._build_firewall_tab()
        self._build_utils_tab()

        # Footer / Status
        footer_frame = ttk.Frame(self)
        footer_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
        footer_frame.columnconfigure(0, weight=1)
        ttk.Label(footer_frame, text="Desenvolvido por Hacking Alchemy", foreground="#888888", font=("Consolas", 10)).grid(row=0, column=1, sticky="e")
        ttk.Label(footer_frame, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

    # --- Tabs builders ---

    def _build_info_tab(self):
        frm = self.tab_info
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Host / IP:").grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.entry_host = ttk.Entry(frm, width=40)
        self.entry_host.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        ttk.Label(frm, text="Token ipinfo (opcional):").grid(row=0, column=2, padx=8, pady=8, sticky="w")
        ttk.Entry(frm, textvariable=self.ipinfo_token, width=30).grid(row=0, column=3, padx=8, pady=8, sticky="ew")

        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=1, column=0, columnspan=4, sticky="ew", padx=8, pady=8)
        ttk.Button(btn_frame, text="Resolver DNS", command=self._async_resolve_dns).grid(row=0, column=0, padx=6)
        ttk.Button(btn_frame, text="Reverse DNS", command=self._async_reverse_dns).grid(row=0, column=1, padx=6)
        ttk.Button(btn_frame, text="WHOIS", command=self._async_whois).grid(row=0, column=2, padx=6)
        ttk.Button(btn_frame, text="Geo/ASN (ipinfo)", command=self._async_ipinfo).grid(row=0, column=3, padx=6)
        ttk.Button(btn_frame, text="Copiar", command=lambda: self._copy_from_text(self.text_info)).grid(row=0, column=4, padx=6)
        ttk.Button(btn_frame, text="Salvar", command=lambda: self._save_text(self.text_info)).grid(row=0, column=5, padx=6)

        self.text_info = scrolledtext.ScrolledText(frm, height=16, wrap="word", background="#222222", foreground="#33FF00", font=("Consolas", 11))
        self.text_info.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=8, pady=8)
        frm.rowconfigure(2, weight=1)

    def _build_port_single_tab(self):
        frm = self.tab_port_single
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Host:").grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.entry_host2 = ttk.Entry(frm, width=32)
        self.entry_host2.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        ttk.Label(frm, text="Porta:").grid(row=1, column=0, padx=8, pady=8, sticky="w")
        self.entry_port2 = ttk.Entry(frm, width=12)
        self.entry_port2.grid(row=1, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm, text="Timeout (s):").grid(row=2, column=0, padx=8, pady=8, sticky="w")
        self.entry_timeout2 = ttk.Entry(frm, width=8)
        self.entry_timeout2.insert(0, "1.5")
        self.entry_timeout2.grid(row=2, column=1, padx=8, pady=8, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=3, column=0, columnspan=2, padx=8, pady=8, sticky="w")
        ttk.Button(btns, text="Verificar Porta", command=self._async_check_port).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Copiar", command=lambda: self._copy_from_text(self.text_port_single)).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Salvar", command=lambda: self._save_text(self.text_port_single)).grid(row=0, column=2, padx=6)

        self.text_port_single = scrolledtext.ScrolledText(frm, height=14, background="#222222", foreground="#33FF00", font=("Consolas", 11))
        self.text_port_single.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=8, pady=8)
        frm.rowconfigure(4, weight=1)

    def _build_port_range_tab(self):
        frm = self.tab_port_range
        for i in range(4):
            frm.columnconfigure(i, weight=1)

        ttk.Label(frm, text="Host:").grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.entry_host_range = ttk.Entry(frm)
        self.entry_host_range.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        ttk.Label(frm, text="Porta inicial:").grid(row=1, column=0, padx=8, pady=8, sticky="w")
        self.entry_start_port = ttk.Entry(frm, width=10)
        self.entry_start_port.insert(0, "1")
        self.entry_start_port.grid(row=1, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm, text="Porta final:").grid(row=1, column=2, padx=8, pady=8, sticky="w")
        self.entry_end_port = ttk.Entry(frm, width=10)
        self.entry_end_port.insert(0, "1024")
        self.entry_end_port.grid(row=1, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm, text="Concorrência:").grid(row=2, column=0, padx=8, pady=8, sticky="w")
        self.spin_workers = ttk.Spinbox(frm, from_=1, to=128, width=8)
        self.spin_workers.set(64)
        self.spin_workers.grid(row=2, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm, text="Timeout (s):").grid(row=2, column=2, padx=8, pady=8, sticky="w")
        self.entry_timeout_range = ttk.Entry(frm, width=8)
        self.entry_timeout_range.insert(0, "0.8")
        self.entry_timeout_range.grid(row=2, column=3, padx=8, pady=8, sticky="w")

        self.progress = ttk.Progressbar(frm, orient="horizontal", mode="determinate")
        self.progress.grid(row=3, column=0, columnspan=4, sticky="ew", padx=8, pady=8)

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=4, sticky="w", padx=8, pady=8)
        self.btn_scan = ttk.Button(btns, text="Iniciar Scan", command=self._async_port_scan)
        self.btn_scan.grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Exportar CSV", command=self._export_scan_csv).grid(row=0, column=1, padx=6)

        # Results Treeview
        columns = ("Porta", "Status", "Serviço")
        self.tree_scan = ttk.Treeview(frm, columns=columns, show="headings", height=16)
        for col in columns:
            self.tree_scan.heading(col, text=col)
        self.tree_scan.column("Porta", width=100, anchor="center")
        self.tree_scan.column("Status", width=140, anchor="center")
        self.tree_scan.column("Serviço", width=280, anchor="w")
        self.tree_scan.grid(row=5, column=0, columnspan=4, sticky="nsew", padx=8, pady=8)
        frm.rowconfigure(5, weight=1)

        self.scan_results = []  # list of dicts

    def _build_http_tab(self):
        frm = self.tab_http
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="URL:").grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.entry_url = ttk.Entry(frm, width=60)
        self.entry_url.insert(0, "https://")
        self.entry_url.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        ttk.Label(frm, text="Método:").grid(row=0, column=2, padx=8, pady=8, sticky="w")
        self.combo_method = ttk.Combobox(frm, values=["GET", "HEAD"], width=8, state="readonly")
        self.combo_method.set("GET")
        self.combo_method.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=1, column=0, columnspan=4, sticky="w", padx=8, pady=8)
        ttk.Button(btns, text="Testar HTTP/HTTPS", command=self._async_http_test).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Copiar", command=lambda: self._copy_from_text(self.text_http)).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Salvar", command=lambda: self._save_text(self.text_http)).grid(row=0, column=2, padx=6)

        self.text_http = scrolledtext.ScrolledText(frm, height=16, background="#222222", foreground="#33FF00", font=("Consolas", 11))
        self.text_http.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=8, pady=8)
        frm.rowconfigure(2, weight=1)

    def _build_firewall_tab(self):
        frm = self.tab_firewall
        for i in range(4):
            frm.columnconfigure(i, weight=1)

        ttk.Label(frm, text="Lista (nome):").grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.entry_list_name = ttk.Entry(frm)
        self.entry_list_name.insert(0, "BlockedRanges")
        self.entry_list_name.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        ttk.Label(frm, text="Ação:").grid(row=0, column=2, padx=8, pady=8, sticky="w")
        self.combo_action = ttk.Combobox(frm, values=["drop", "reject"], state="readonly")
        self.combo_action.set("drop")
        self.combo_action.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm, text="Chain:").grid(row=1, column=0, padx=8, pady=8, sticky="w")
        self.combo_chain = ttk.Combobox(frm, values=["input", "forward", "output"], state="readonly")
        self.combo_chain.set("input")
        self.combo_chain.grid(row=1, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm, text="Comentário:").grid(row=1, column=2, padx=8, pady=8, sticky="w")
        self.entry_comment = ttk.Entry(frm)
        self.entry_comment.insert(0, "Block traffic from specific IP ranges")
        self.entry_comment.grid(row=1, column=3, padx=8, pady=8, sticky="ew")

        ttk.Label(frm, text="Vendor:").grid(row=2, column=0, padx=8, pady=8, sticky="w")
        self.combo_vendor = ttk.Combobox(frm, values=["MikroTik", "iptables", "pfSense (pfctl)", "FortiGate"], state="readonly")
        self.combo_vendor.set("MikroTik")
        self.combo_vendor.grid(row=2, column=1, padx=8, pady=8, sticky="w")

        ttk.Button(frm, text="Carregar Arquivo de IPs/CIDRs", command=self._load_ip_file).grid(row=2, column=2, padx=8, pady=8, sticky="w")
        ttk.Button(frm, text="Gerar Regras", command=self._generate_firewall_rules).grid(row=2, column=3, padx=8, pady=8, sticky="w")

        self.text_firewall = scrolledtext.ScrolledText(frm, height=16, background="#222222", foreground="#33FF00", font=("Consolas", 11))
        self.text_firewall.grid(row=3, column=0, columnspan=4, sticky="nsew", padx=8, pady=8)
        frm.rowconfigure(3, weight=1)

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=4, sticky="w", padx=8, pady=8)
        ttk.Button(btns, text="Copiar", command=lambda: self._copy_from_text(self.text_firewall)).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Salvar", command=lambda: self._save_text(self.text_firewall)).grid(row=0, column=1, padx=6)

        self.loaded_ips = []

    def _build_utils_tab(self):
        frm = self.tab_utils
        for i in range(4):
            frm.columnconfigure(i, weight=1)

        ttk.Label(frm, text="Host/IP (Ping/Traceroute):").grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.entry_utils_host = ttk.Entry(frm)
        self.entry_utils_host.grid(row=0, column=1, padx=8, pady=8, sticky="ew")

        ttk.Label(frm, text="Contagem de pacotes (ping):").grid(row=0, column=2, padx=8, pady=8, sticky="w")
        self.entry_ping_count = ttk.Entry(frm, width=8)
        self.entry_ping_count.insert(0, "4")
        self.entry_ping_count.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=1, column=0, columnspan=4, sticky="w", padx=8, pady=8)
        ttk.Button(btns, text="Ping", command=self._async_ping).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Traceroute", command=self._async_traceroute).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Copiar", command=lambda: self._copy_from_text(self.text_utils)).grid(row=0, column=2, padx=6)
        ttk.Button(btns, text="Salvar", command=lambda: self._save_text(self.text_utils)).grid(row=0, column=3, padx=6)

        self.text_utils = scrolledtext.ScrolledText(frm, height=18, background="#222222", foreground="#33FF00", font=("Consolas", 11))
        self.text_utils.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=8, pady=8)
        frm.rowconfigure(2, weight=1)

    # --- Helpers for clipboard/save ---

    def _copy_from_text(self, text_widget):
        try:
            content = text_widget.get('1.0', tk.END).strip()
            self.clipboard_clear()
            self.clipboard_append(content)
            self.status_var.set("Conteúdo copiado para a área de transferência.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao copiar: {e}")

    def _save_text(self, text_widget):
        try:
            content = text_widget.get('1.0', tk.END).strip()
            if not content:
                messagebox.showwarning("Aviso", "Nada para salvar.")
                return
            fname = asksaveasfilename(defaultextension=".txt", filetypes=[("Texto", "*.txt"), ("Todos", "*.*")])
            if not fname:
                return
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            self.status_var.set(f"Arquivo salvo em: {fname}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar: {e}")

    def _set_busy(self, widget_list, busy=True):
        for w in widget_list:
            try:
                w.configure(state="disabled" if busy else "normal")
            except Exception:
                pass
        self.status_var.set("Processando..." if busy else "Pronto.")

    # --- Async wrappers (threading) ---

    def _async_resolve_dns(self):
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Aviso", "Informe um host/IP.")
            return
        btns = [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_resolve_dns, args=(host,), daemon=True).start()

    def _do_resolve_dns(self, host):
        try:
            ip, family = resolve_host(host)
            fam_name = "IPv4" if family == socket.AF_INET else "IPv6"
            info = f"[{timestamp()}] RESOLVE DNS\nHost: {host}\nIP: {ip}\nFamília: {fam_name}\n"
            self.text_info.after(0, safe_insert_text, self.text_info, info)
        except Exception as e:
            self.text_info.after(0, safe_insert_text, self.text_info, f"Erro: {e}")
        finally:
            self.text_info.after(0, self._set_busy, [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

    def _async_reverse_dns(self):
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Aviso", "Informe um host/IP.")
            return
        btns = [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_reverse_dns, args=(host,), daemon=True).start()

    def _do_reverse_dns(self, host):
        try:
            ip = host if is_valid_ip(host) else resolve_host(host)[0]
            name, alias, _ = socket.gethostbyaddr(ip)
            info = f"[{timestamp()}] REVERSE DNS\nIP: {ip}\nHostname: {name}\nAliases: {', '.join(alias) if alias else 'N/A'}\n"
            self.text_info.after(0, safe_insert_text, self.text_info, info)
        except Exception as e:
            self.text_info.after(0, safe_insert_text, self.text_info, f"Erro: {e}")
        finally:
            self.text_info.after(0, self._set_busy, [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

    def _async_whois(self):
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Aviso", "Informe um domínio (ex: exemplo.com).")
            return
        btns = [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_whois, args=(host,), daemon=True).start()

    def _do_whois(self, domain):
        text = whois_query(domain)
        self.text_info.after(0, safe_insert_text, self.text_info, f"[{timestamp()}] WHOIS - {domain}\n\n{text}")
        self.text_info.after(0, self._set_busy, [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

    def _async_ipinfo(self):
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Aviso", "Informe um host/IP.")
            return
        btns = [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_ipinfo, args=(host,), daemon=True).start()

    def _do_ipinfo(self, host):
        try:
            ip = host if is_valid_ip(host) else resolve_host(host)[0]
            token = self.ipinfo_token.get().strip()
            url = f"https://ipinfo.io/{ip}/json"
            headers = {}
            params = {}
            if token:
                params['token'] = token
            resp = requests.get(url, headers=headers, params=params, timeout=7)
            resp.raise_for_status()
            data = resp.json()
            result_text = (f"[{timestamp()}] ipinfo.io\n"
                           f"IP: {data.get('ip','N/A')}\n"
                           f"Cidade: {data.get('city','N/A')}\n"
                           f"Região: {data.get('region','N/A')}\n"
                           f"País: {data.get('country','N/A')}\n"
                           f"Localização: {data.get('loc','N/A')}\n"
                           f"Timezone: {data.get('timezone','N/A')}\n"
                           f"Org/ASN: {data.get('org','N/A')}\n")
            self.text_info.after(0, safe_insert_text, self.text_info, result_text)
        except Exception as e:
            self.text_info.after(0, safe_insert_text, self.text_info, f"Erro ao obter informações: {e}")
        finally:
            self.text_info.after(0, self._set_busy, [child for child in self.tab_info.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

    def _async_check_port(self):
        host = self.entry_host2.get().strip()
        port = self.entry_port2.get().strip()
        timeout = self.entry_timeout2.get().strip()
        if not host or not port:
            messagebox.showwarning("Aviso", "Informe host e porta.")
            return
        try:
            port = int(port)
            timeout = float(timeout)
        except ValueError:
            messagebox.showerror("Erro", "Porta/Timeout inválidos.")
            return

        btns = [child for child in self.tab_port_single.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_check_port, args=(host, port, timeout), daemon=True).start()

    def _do_check_port(self, host, port, timeout):
        try:
            ip = host if is_valid_ip(host) else resolve_host(host)[0]
            opened = tcp_check(ip, port, timeout)
            service = COMMON_PORTS.get(port, "Desconhecido")
            result_text = (f"[{timestamp()}] Verificação de Porta\n"
                           f"Host: {host} (IP: {ip})\nPorta: {port}\n"
                           f"Status: {'ABERTA' if opened else 'FECHADA'}\n"
                           f"Serviço esperado: {service}\n")
            self.text_port_single.after(0, safe_insert_text, self.text_port_single, result_text)
        except Exception as e:
            self.text_port_single.after(0, safe_insert_text, self.text_port_single, f"Erro: {e}")
        finally:
            self.text_port_single.after(0, self._set_busy, [child for child in self.tab_port_single.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

    def _async_port_scan(self):
        host = self.entry_host_range.get().strip()
        try:
            start = int(self.entry_start_port.get().strip())
            end = int(self.entry_end_port.get().strip())
            timeout = float(self.entry_timeout_range.get().strip())
            workers = int(self.spin_workers.get().strip())
        except ValueError:
            messagebox.showerror("Erro", "Valores inválidos de porta/timeout/conhecimento.")
            return
        if not host:
            messagebox.showwarning("Aviso", "Informe um host.")
            return
        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("Erro", "Intervalo de portas inválido.")
            return

        self._set_busy([self.btn_scan], True)
        self.tree_scan.delete(*self.tree_scan.get_children())
        self.scan_results = []
        threading.Thread(target=self._do_port_scan, args=(host, start, end, timeout, workers), daemon=True).start()

    def _do_port_scan(self, host, start, end, timeout, workers):
        try:
            ip = host if is_valid_ip(host) else resolve_host(host)[0]
            total = end - start + 1
            self.progress.after(0, self.progress.configure, {'maximum': total, 'value': 0})

            def probe(p):
                ok = tcp_check(ip, p, timeout)
                svc = COMMON_PORTS.get(p, "")
                return (p, ok, svc)

            done = 0
            with ThreadPoolExecutor(max_workers=workers) as ex:
                for p, ok, svc in ex.map(probe, range(start, end + 1)):
                    self.scan_results.append({"port": p, "open": ok, "service": svc})
                    self.tree_scan.after(0, self._append_scan_row, p, ok, svc)
                    done += 1
                    if done % 10 == 0 or done == total:
                        self.progress.after(0, self.progress.configure, {'value': done})
            self.status_var.set("Scan concluído.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha no scan: {e}")
        finally:
            self.progress.after(0, self.progress.configure, {'value': 0})
            self._set_busy([self.btn_scan], False)

    def _append_scan_row(self, port, ok, svc):
        status = "ABERTA" if ok else "fechada"
        self.tree_scan.insert("", "end", values=(port, status, svc))

    def _export_scan_csv(self):
        if not self.scan_results:
            messagebox.showwarning("Aviso", "Nenhum resultado para exportar.")
            return
        path = asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("Todos", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["port", "open", "service"])
                w.writeheader()
                for r in self.scan_results:
                    w.writerow(r)
            self.status_var.set(f"Exportado para {path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar: {e}")

    def _async_http_test(self):
        url = self.entry_url.get().strip()
        method = self.combo_method.get()
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            messagebox.showwarning("Aviso", "Informe uma URL iniciando com http:// ou https://")
            return
        btns = [child for child in self.tab_http.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_http_test, args=(url, method), daemon=True).start()

    def _do_http_test(self, url, method):
        start = time.time()
        try:
            if method == "GET":
                resp = requests.get(url, timeout=8)
            else:
                resp = requests.head(url, timeout=8)
            elapsed = (time.time() - start) * 1000
            headers_str = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
            result = (f"[{timestamp()}] HTTP TEST\nURL: {url}\nMétodo: {method}\n"
                      f"Status: {resp.status_code}\nTempo: {elapsed:.1f} ms\n\nHeaders:\n{headers_str}\n")
            # TLS cert for HTTPS
            if url.lower().startswith("https://"):
                try:
                    host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
                    cert = https_certificate_info(host)
                    if "error" in cert:
                        result += f"\nCertificado TLS: erro: {cert['error']}\n"
                    else:
                        subj = cert['subject']
                        iss = cert['issuer']
                        result += ("\nCertificado TLS:\n"
                                   f"  Subject CN: {subj.get('commonName','N/A')}\n"
                                   f"  Issuer CN: {iss.get('commonName','N/A')}\n"
                                   f"  Válido de: {cert['not_before']}\n"
                                   f"  Válido até: {cert['not_after']}\n"
                                   f"  SANs: {', '.join(cert['san_dns']) if cert['san_dns'] else 'N/A'}\n")
                except Exception as e:
                    result += f"\nCertificado TLS: erro ao processar: {e}\n"
            self.text_http.after(0, safe_insert_text, self.text_http, result)
        except Exception as e:
            self.text_http.after(0, safe_insert_text, self.text_http, f"Erro HTTP: {e}")
        finally:
            self.text_http.after(0, self._set_busy, [child for child in self.tab_http.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

    def _load_ip_file(self):
        filename = askopenfilename(filetypes=[("Text Files", "*.txt"), ("Todos", "*.*")])
        if not filename:
            return
        try:
            with open(filename, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            ips = []
            for ip in lines:
                try:
                    if "/" in ip:
                        ipaddress.ip_network(ip, strict=False)  # validate CIDR
                        ips.append(ip)
                    else:
                        ipaddress.ip_address(ip)
                        ips.append(ip + "/32")
                except ValueError:
                    # Skip invalid
                    pass
            self.loaded_ips = ips
            safe_insert_text(self.text_firewall, f"[{timestamp()}] Carregados {len(ips)} itens do arquivo.\n")
            self.status_var.set(f"Arquivo carregado: {filename}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao ler arquivo: {e}")

    def _generate_firewall_rules(self):
        if not self.loaded_ips:
            messagebox.showwarning("Aviso", "Carregue antes um arquivo de IPs/CIDRs.")
            return
        list_name = self.entry_list_name.get().strip() or "BlockedRanges"
        action = self.combo_action.get()
        chain = self.combo_chain.get()
        comment = self.entry_comment.get().strip()
        vendor = self.combo_vendor.get()

        rules = []
        if vendor == "MikroTik":
            for cidr in self.loaded_ips:
                rules.append(f"/ip firewall address-list add list={list_name} address={cidr}")
            rules.append(f"/ip firewall filter add action={action} chain={chain} src-address-list={list_name} comment=\"{comment}\"")
        elif vendor == "iptables":
            # Requires runtime substitution; examples for IPv4
            for cidr in self.loaded_ips:
                rules.append(f"iptables -A {chain} -s {cidr} -j {action.upper()}")
            rules.append(f"# Persistência depende de distro (ex: iptables-save)")
        elif vendor == "pfSense (pfctl)":
            rules.append(f"table <{list_name}> {{")
            for cidr in self.loaded_ips:
                rules.append(f"  {cidr}")
            rules.append("}")
            rules.append(f"block in quick from <{list_name}> to any # " + comment)
        elif vendor == "FortiGate":
            rules.append(f"config firewall address")
            for i, cidr in enumerate(self.loaded_ips, start=1):
                name = f"{list_name}_{i}"
                rules.append(f"    edit {name}")
                rules.append(f"        set subnet {cidr}")
                rules.append(f"    next")
            rules.append(f"end")
            rules.append(f"config firewall addrgrp")
            rules.append(f"    edit {list_name}")
            rules.append(f"        set member " + " ".join([f"{list_name}_{i}" for i in range(1, len(self.loaded_ips)+1)]))
            rules.append(f"    next")
            rules.append(f"end")
            rules.append(f"# Criar política usando grupo {list_name} com ação {action}")
        else:
            rules.append("# Vendor não suportado.")

        safe_insert_text(self.text_firewall, "\n".join(rules))

    def _async_ping(self):
        host = self.entry_utils_host.get().strip()
        if not host:
            messagebox.showwarning("Aviso", "Informe um host/IP.")
            return
        btns = [child for child in self.tab_utils.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_ping, args=(host,), daemon=True).start()

    def _do_ping(self, host):
        count = self.entry_ping_count.get().strip()
        try:
            c = int(count)
        except ValueError:
            c = 4
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", str(c), host]
        else:
            cmd = ["ping", "-c", str(c), host]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            result = f"[{timestamp()}] PING {host}\n\n{out.stdout or out.stderr}"
            self.text_utils.after(0, safe_insert_text, self.text_utils, result)
        except Exception as e:
            self.text_utils.after(0, safe_insert_text, self.text_utils, f"Erro ping: {e}")
        finally:
            self.text_utils.after(0, self._set_busy, [child for child in self.tab_utils.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

    def _async_traceroute(self):
        host = self.entry_utils_host.get().strip()
        if not host:
            messagebox.showwarning("Aviso", "Informe um host/IP.")
            return
        btns = [child for child in self.tab_utils.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children()
        self._set_busy(btns, True)
        threading.Thread(target=self._do_traceroute, args=(host,), daemon=True).start()

    def _do_traceroute(self, host):
        system = platform.system().lower()
        if system == "windows":
            cmd = ["tracert", host]
        else:
            cmd = ["traceroute", host]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            result = f"[{timestamp()}] TRACEROUTE {host}\n\n{out.stdout or out.stderr}"
            self.text_utils.after(0, safe_insert_text, self.text_utils, result)
        except Exception as e:
            self.text_utils.after(0, safe_insert_text, self.text_utils, f"Erro traceroute: {e}")
        finally:
            self.text_utils.after(0, self._set_busy, [child for child in self.tab_utils.winfo_children() if isinstance(child, ttk.Frame)][0].winfo_children(), False)

if __name__ == "__main__":
    app = SOCApp()
    app.mainloop()
