import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
import requests

# Função para verificar os cabeçalhos de segurança e serviços de proteção
def verificar_cabecalhos():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Erro", "Por favor, insira uma URL válida.")
        return

    # Tentando realizar a requisição
    try:
        response = requests.get(url)
        cabecalhos = response.headers

        # Analisando os cabeçalhos
        resultados.delete(1.0, tk.END)  # Limpa a área de resultados

        cabecalhos_essenciais = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
        cabecalhos_bem_configurados = []
        cabecalhos_fracos = []

        for cabecalho in cabecalhos_essenciais:
            if cabecalho in cabecalhos:
                if cabecalho == 'X-XSS-Protection' and cabecalhos[cabecalho] == '0':
                    cabecalhos_fracos.append(cabecalho)
                else:
                    cabecalhos_bem_configurados.append(cabecalho)
            else:
                cabecalhos_fracos.append(cabecalho)

        # Verificar proteção por serviços como Cloudflare, Akamai, Sucuri
        protecao_detectada = detectar_servicos_protecao(cabecalhos)

        # Exibindo os resultados de forma organizada
        resultados.insert(tk.END, "Resultados para: " + url + "\n\n")
        
        # Cabeçalhos bem configurados
        if cabecalhos_bem_configurados:
            resultados.insert(tk.END, "Cabeçalhos de segurança bem configurados:\n", 'good')
            for cabecalho in cabecalhos_bem_configurados:
                resultados.insert(tk.END, f"- {cabecalho}\n", 'good')
        else:
            resultados.insert(tk.END, "Nenhum cabeçalho de segurança bem configurado encontrado.\n", 'bad')

        # Cabeçalhos fracos
        if cabecalhos_fracos:
            resultados.insert(tk.END, "\nCabeçalhos de segurança fracos ou mal configurados:\n", 'warning')
            for cabecalho in cabecalhos_fracos:
                resultados.insert(tk.END, f"- {cabecalho}\n", 'warning')
        else:
            resultados.insert(tk.END, "Nenhum cabeçalho de segurança fraco encontrado.\n", 'good')

        # Proteções detectadas
        if protecao_detectada:
            resultados.insert(tk.END, "\nServiços de proteção detectados:\n", 'protection')
            for protecao in protecao_detectada:
                resultados.insert(tk.END, f"- {protecao}\n", 'protection')
        else:
            resultados.insert(tk.END, "Nenhum serviço de proteção detectado.\n", 'bad')

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Erro", f"Não foi possível acessar a URL. Verifique a conexão ou a URL inserida.\n{e}")

# Função para detectar serviços de proteção (Cloudflare, Akamai, Sucuri, etc.)
def detectar_servicos_protecao(cabecalhos):
    protecao = []

    # Verificar Cloudflare
    if 'CF-RAY' in cabecalhos or 'Server' in cabecalhos and 'cloudflare' in cabecalhos['Server'].lower():
        protecao.append("Cloudflare")

    # Verificar Akamai
    if 'X-Akamai-Transformed' in cabecalhos or 'Akamai-Origin-Hop' in cabecalhos or 'Edge-Control' in cabecalhos:
        protecao.append("Akamai")

    # Verificar Sucuri
    if 'Server' in cabecalhos and 'Sucuri/Cloudproxy' in cabecalhos['Server']:
        protecao.append("Sucuri")

    return protecao

# Função para gerar um relatório simples
def gerar_relatorio():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Erro", "Por favor, insira uma URL válida.")
        return

    try:
        with open("relatorio_cabecalhos.txt", "w") as f:
            f.write("Relatório de Cabeçalhos de Segurança para: " + url + "\n\n")
            for tag in resultados.get(1.0, tk.END).splitlines():
                f.write(tag + "\n")
        messagebox.showinfo("Sucesso", "Relatório gerado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao gerar relatório: {e}")

# Função para configurar o estilo da interface
def aplicar_estilo():
    # Estilizando a área de resultados
    resultados.tag_configure('good', foreground='green', font=('Arial', 10, 'bold'))
    resultados.tag_configure('warning', foreground='orange', font=('Arial', 10, 'bold'))
    resultados.tag_configure('bad', foreground='red', font=('Arial', 10, 'bold'))
    resultados.tag_configure('protection', foreground='blue', font=('Arial', 10, 'bold'))

# Criando a janela principal
root = tk.Tk()
root.title("Verificador de Cabeçalhos de Segurança")
root.geometry("600x500")
root.config(bg="#f0f0f0")

# Título
titulo = tk.Label(root, text="Analisador de Cabeçalhos de Segurança", font=("Arial", 16, 'bold'), bg="#f0f0f0")
titulo.pack(pady=10)

# Entrada de URL
url_label = tk.Label(root, text="Insira a URL para verificar os cabeçalhos de segurança:", font=("Arial", 10), bg="#f0f0f0")
url_label.pack(pady=5)

url_entry = tk.Entry(root, width=50, font=("Arial", 10))
url_entry.pack(pady=5)

# Botão para verificar cabeçalhos
verificar_button = tk.Button(root, text="Verificar", font=("Arial", 10, 'bold'), bg="blue", fg="white", command=verificar_cabecalhos)
verificar_button.pack(pady=10)

# Área de resultados
resultados = scrolledtext.ScrolledText(root, width=70, height=15, font=("Arial", 10), wrap=tk.WORD, bg="#ffffff", fg="#000000")
resultados.pack(pady=10)

# Botão para gerar relatório
gerar_relatorio_button = tk.Button(root, text="Gerar Relatório", font=("Arial", 10, 'bold'), bg="green", fg="white", command=gerar_relatorio)
gerar_relatorio_button.pack(pady=10)

# Aplicando o estilo de cores
aplicar_estilo()

# Iniciando a interface
root.mainloop()
