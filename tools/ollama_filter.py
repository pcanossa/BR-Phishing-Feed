import os
import sys
import time
import json
import sqlite3
import datetime

# Adiciona o diretório raiz do projeto ao path do Python para encontrar a pasta 'prompts'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ollama_engine import ollama_engine
from prompts.filter_phish import generate_phishing_prompt as phishing_prompt

def conectar_banco():
    # Cria (ou conecta) ao arquivo do banco de dados na pasta database
    os.makedirs('./database', exist_ok=True)
    conn = sqlite3.connect('./database/historico_cti.db')
    cursor = conn.cursor()
    
    # Cria a tabela definindo o domínio como chave primária para busca ultrarrápida
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analises (
            dominio TEXT PRIMARY KEY,
            status TEXT,
            data_analise TEXT
        )
    ''')
    conn.commit()
    return conn

def ollama_filter(dominio, conn):
    cursor = conn.cursor()
    
    # 1. VERIFICAÇÃO DE CACHE RÁPIDO NO BANCO (Substitui a leitura de disco)
    cursor.execute("SELECT status FROM analises WHERE dominio = ?", (dominio,))
    resultado = cursor.fetchone()
    
    if resultado:
        print(f"[+] Domínio '{dominio}' já analisado anteriormente (Status: {resultado[0]}). Pulando...")
        return

    print(f"[+] Domínio '{dominio}' não está no banco. Iniciando análise com a IA local...")
    
    prompt = phishing_prompt()
    final_message = [
        {'role': 'system', 'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts e comportamentos maliciosos.'},
        {'role': 'user', 'content': prompt},
        {'role': 'user', 'content': dominio}
    ] 

    try:
        # Comunicação com o Ollama rodando localmente
        full_response = ollama_engine(message=final_message)
    except Exception as e:
        # Removido o sys.exit(1) para que o script não morra caso o Ollama engasgue temporariamente
        print(f"[-] Erro de conexão com o Ollama local para o domínio '{dominio}': {e}")
        return
        
    try:
        # Extrai de forma segura o JSON da resposta do LLM
        json_str = full_response.strip()
        start_idx = json_str.find('{')
        end_idx = json_str.rfind('}')
        
        if start_idx != -1 and end_idx != -1:
            json_str = json_str[start_idx:end_idx+1]
            
        response_json = json.loads(json_str)
        categoria = str(response_json.get("categoria_ameaca", "")).lower()
        
        data_atual = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Lógica de Falso Positivo (Benigno)
        if categoria == "false":
            print(f"[!] Falso positivo. Salvando '{dominio}' apenas no banco de dados.")
            cursor.execute("INSERT INTO analises (dominio, status, data_analise) VALUES (?, ?, ?)", 
                           (dominio, "benigno", data_atual))
            conn.commit()
            return
            
        # Lógica de Ameaça Real (Maligno)
        print(f"[!!!] AMEAÇA CONFIRMADA: Salvando JSON de '{dominio}' no feed e registrando no banco.")
        
        cursor.execute("INSERT INTO analises (dominio, status, data_analise) VALUES (?, ?, ?)", 
                       (dominio, "maligno", data_atual))
        conn.commit()
        
        # Gera o artefato físico para a pasta de feed
        report_filename = f"{dominio}.json"
        report_path = f"./phishing_domain_feed/{report_filename}"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(response_json, f, indent=4, ensure_ascii=False)
            
    except json.JSONDecodeError as e:
        print(f"[-] Erro ao fazer o parse do JSON do LLM: {e}. Salvando formato bruto para debug...")
        report_filename = f"{dominio}_erro_sintaxe.txt"
        report_path = f"./phishing_domain_feed/{report_filename}"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(full_response)

# ==========================================
# MAIN LOOP DO DAEMON
# ==========================================
# Instancia o banco apenas uma vez ao iniciar o script
conexao_banco = conectar_banco()

while True:
    if os.path.exists("./logs"):
        for file in os.listdir("./logs"):
            if file.endswith(".json"):
                with open(f"./logs/{file}", "r", encoding="utf-8") as f:
                    content = f.read()

                    decoder = json.JSONDecoder()
                    pos = 0

                    # Faz a varredura lendo múltiplos pacotes JSON dentro do mesmo arquivo de log
                    while pos < len(content):
                        while pos < len(content) and content[pos].isspace():
                            pos += 1
                        if pos >= len(content):
                            break
                        try:
                            data, pos = decoder.raw_decode(content, pos)
                            if 'dominio' in data:
                                # Injeta a conexão do banco e envia para a esteira de análise
                                ollama_filter(data['dominio'], conexao_banco)
                                time.sleep(20)  # Pequena pausa entre análises para evitar sobrecarga
                        except json.JSONDecodeError as e:
                            print(f"[-] Erro ao decodificar pacote JSON no arquivo {file}: {e}")
                            break
                            
    # Previne que o loop sobrecarregue a CPU quando não houver logs na pasta
    time.sleep(5)