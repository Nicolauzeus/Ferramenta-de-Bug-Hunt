import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import socket
from fpdf import FPDF

# Chave da API do VirusTotal
VT_API_KEY = "c11a3025cf915dd454113b580a13cb4ff7973f78c771bb3f7cb0f42624f19a01"

# Função para buscar subdomínios usando a API do VirusTotal
def get_subdomains_virustotal(domain):
    try:
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {"apikey": VT_API_KEY, "domain": domain}
        
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            data = response.json()
            if "subdomains" in data:
                subdomains = data["subdomains"]
                return subdomains
            else:
                messagebox.showinfo("Informação", "Nenhum subdomínio encontrado.")
                return []
        else:
            messagebox.showerror("Erro", f"Falha ao buscar subdomínios: {response.status_code}")
            return []
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao buscar subdomínios: {str(e)}")
        return []

# Função para verificar portas abertas
def check_ports(domain, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Timeout de 1 segundo
                result = s.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
        except socket.error as e:
            messagebox.showerror("Erro", f"Erro ao verificar portas: {str(e)}")
    return open_ports

# Função para gerar relatório em PDF
def generate_pdf_report(domain, subdomains, open_ports):
    try:
        # Cria o objeto PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)

        # Título
        pdf.cell(200, 10, "Relatório de Segurança - Nicolau Zeus 7", ln=True, align="C")

        # Informações do domínio
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, f"Domínio: {domain}", ln=True)
        
        # Subdomínios encontrados
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, "Subdomínios encontrados:", ln=True)
        pdf.set_font("Arial", "", 12)
        if subdomains:
            for subdomain in subdomains:
                pdf.cell(200, 10, subdomain, ln=True)
        else:
            pdf.cell(200, 10, "Nenhum subdomínio encontrado.", ln=True)

        # Portas abertas
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, "Portas abertas:", ln=True)
        pdf.set_font("Arial", "", 12)
        if open_ports:
            for port in open_ports:
                pdf.cell(200, 10, f"Porta {port} aberta", ln=True)
        else:
            pdf.cell(200, 10, "Nenhuma porta aberta encontrada.", ln=True)

        # Salvar o PDF
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if file_path:
            pdf.output(file_path)
            messagebox.showinfo("Sucesso", "Relatório PDF gerado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao gerar relatório PDF: {str(e)}")

# Função para iniciar o teste de vulnerabilidades
def test_vulnerabilities():
    domain = entry_url.get()
    if not domain:
        messagebox.showwarning("Aviso", "Por favor, insira um domínio.")
        return

    # Exibe progresso
    progress_label['text'] = "Buscando subdomínios..."
    progress_bar['value'] = 0
    window.update_idletasks()

    # Atualiza a porcentagem de progresso durante a busca
    for i in range(0, 101, 10):
        progress_bar['value'] = i
        window.update_idletasks()

    # Busca subdomínios usando VirusTotal API
    subdomains = get_subdomains_virustotal(domain)
    
    if subdomains:
        subdomain_listbox.delete(0, tk.END)  # Limpa a lista
        for sub in subdomains:
            subdomain_listbox.insert(tk.END, sub)

        # Verifica portas abertas
        ports_input = entry_ports.get()
        if ports_input:
            ports = [int(port.strip()) for port in ports_input.split(",")]
            open_ports = check_ports(domain, ports)
            port_listbox.delete(0, tk.END)  # Limpa a lista de portas
            if open_ports:
                for port in open_ports:
                    port_listbox.insert(tk.END, f"Porta {port} aberta")
            else:
                port_listbox.insert(tk.END, "Nenhuma porta aberta encontrada.")
        
        progress_label['text'] = f"Encontrados {len(subdomains)} subdomínios."
        progress_bar['value'] = 100
        progress_label.config(fg="green")
    else:
        progress_label['text'] = "Nenhum subdomínio encontrado."
        progress_label.config(fg="red")
        progress_bar['value'] = 100

# Função para gerar relatório em PDF
def generate_report():
    domain = entry_url.get()
    subdomains = subdomain_listbox.get(0, tk.END)
    open_ports = port_listbox.get(0, tk.END)
    if not domain or not subdomains:
        messagebox.showwarning("Aviso", "Por favor, insira um domínio e execute o teste.")
        return
    generate_pdf_report(domain, subdomains, open_ports)

# Interface Gráfica
window = tk.Tk()
window.title("Nicolau Zeus 7 - Bug Hunt")
window.configure(bg="#001f3f")  # Cor azul mais escura

# Título
title_label = tk.Label(window, text="Nicolau Zeus 7", font=("Arial", 20), fg="white", bg="#001f3f")  # Cor mais escura
title_label.pack(pady=10)

# Subtítulo
subtitle_label = tk.Label(window, text="Bug Hunt", font=("Arial", 14), fg="white", bg="#001f3f")  # Cor mais escura
subtitle_label.pack(pady=5)

# Entrada de URL
entry_url = tk.Entry(window, width=50, bg="white", fg="black")
entry_url.pack(pady=10)

# Entrada de Portas
entry_ports = tk.Entry(window, width=50, bg="white", fg="black")
entry_ports.pack(pady=5)
entry_ports.insert(0, "21,22,80,443,8080")  # Exemplo de portas a serem verificadas

# Botão para iniciar o teste
start_button = tk.Button(window, text="Iniciar Teste", command=test_vulnerabilities, bg="white", fg="black")
start_button.pack(pady=10)

# Barra de progresso
progress_label = tk.Label(window, text="Iniciando...", font=("Arial", 10), fg="white", bg="#001f3f")  # Cor mais escura
progress_label.pack(pady=5)

# Barra de progresso visual
progress_bar = ttk.Progressbar(window, length=300, mode="determinate", maximum=100)
progress_bar.pack(pady=10)

# Lista de subdomínios encontrados
subdomain_listbox = tk.Listbox(window, width=60, height=10, bg="white", fg="black")
subdomain_listbox.pack(pady=10)

# Lista de portas abertas
port_listbox = tk.Listbox(window, width=60, height=5, bg="white", fg="black")
port_listbox.pack(pady=10)

# Botão para gerar relatório PDF
report_button = tk.Button(window, text="Gerar Relatório PDF", command=generate_report, bg="white", fg="black")
report_button.pack(pady=10)

window.mainloop()

