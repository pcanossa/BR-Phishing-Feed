import google.generativeai as genai
import os
import time
import json
import sys
from dotenv import load_dotenv
import sqlite3
import datetime

# 1. Carrega as variáveis do arquivo .env ANTES de tentar ler a chave
load_dotenv()

# Adiciona o diretório raiz do projeto ao path do Python para encontrar a pasta 'prompts'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prompts.filter_phish import generate_phishing_prompt as phishing_prompt

# 2. Instancia a API do Google uma única vez globalmente
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError("Chave GEMINI_API_KEY não encontrada no arquivo .env.")
genai.configure(api_key=api_key)

def ollama_engine(message):
    # Instancia o modelo leve da família Gemini 3 (Cota de 500/dia)
    model = genai.GenerativeModel('gemini-3.1-flash-lite-preview')

    prompt_completo = ""
    for msg in message:
        prompt_completo += f"{msg['content']}\n\n"

    while True:
        try:
            response = model.generate_content(prompt_completo)
            return response.text
        except Exception as e:
            print(f"\n[!] Erro na API do Gemini: {e}")
            print("[*] Possível Rate Limit. Aguardando 60 segundos antes de tentar novamente...")
            time.sleep(60) 
            print("[*] Fim da pausa. Tentando reconectar...")

def conectar_banco():
    # Cria (ou conecta) ao arquivo do banco de dados
    # Ajustei o caminho para salvar o banco na mesma pasta do script, ou mude para onde preferir.
    conn = sqlite3.connect('./database/historico_cti.db')
    cursor = conn.cursor()
    
    # Cria a tabela definindo o domínio como chave primária
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
    
    # 1. VERIFICAÇÃO DE CACHE RÁPIDO NO BANCO
    cursor.execute("SELECT status FROM analises WHERE dominio = ?", (dominio,))
    resultado = cursor.fetchone()
    
    if resultado:
        print(f"[+] Domínio '{dominio}' já analisado anteriormente (Status: {resultado[0]}). Pulando...")
        return

    print(f"[+] Domínio '{dominio}' não está no banco. Iniciando análise com a IA...")
    
    prompt = phishing_prompt()
    final_message = [
        {'role': 'system', 'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts e comportamentos maliciosos.'},
        {'role': 'user', 'content': prompt},
        {'role': 'user', 'content': dominio}
    ] 

    try:
        full_response = ollama_engine(message=final_message)
    except Exception as e:
        print(f"[-] Erro crítico ao se comunicar com a IA para '{dominio}': {e}")
        sys.exit(1)
        
    try:
        json_str = full_response.strip()
        start_idx = json_str.find('{')
        end_idx = json_str.rfind('}')
        if start_idx != -1 and end_idx != -1:
            json_str = json_str[start_idx:end_idx+1]
            
        response_json = json.loads(json_str)
        categoria = str(response_json.get("categoria_ameaca", "")).lower()
        
        data_atual = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if categoria == "false":
            print(f"[!] Falso positivo. Salvando '{dominio}' apenas no banco de dados.")
            # Insere no banco como benigno
            cursor.execute("INSERT INTO analises (dominio, status, data_analise) VALUES (?, ?, ?)", 
                           (dominio, "benigno", data_atual))
            conn.commit()
            return
            
        # SE CHEGOU AQUI, É MALIGNO DE VERDADE
        print(f"[!!!] AMEAÇA CONFIRMADA: Salvando JSON de '{dominio}' no feed e registrando no banco.")
        
        # Insere no banco como maligno
        cursor.execute("INSERT INTO analises (dominio, status, data_analise) VALUES (?, ?, ?)", 
                       (dominio, "maligno", data_atual))
        conn.commit()
        
        # Só agora salva o JSON físico na pasta do Feed
        report_filename = f"{dominio}.json"
        report_path = f"./phishing_domain_feed/{report_filename}"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(response_json, f, indent=4, ensure_ascii=False)
            
    except json.JSONDecodeError as e:
        print(f"[-] Erro ao decodificar JSON: {e}")

# ==========================================
# MAIN LOOP
# ==========================================
# Inicia a conexão com o banco UMA VEZ antes do laço
conexao_banco = conectar_banco()

while True:
    if os.path.exists("./logs"):
        for file in os.listdir("./logs"):
            if file.endswith(".json"):
                with open(f"./logs/{file}", "r", encoding="utf-8") as f:
                    content = f.read()

                    decoder = json.JSONDecoder()
                    pos = 0

                    while pos < len(content):
                        while pos < len(content) and content[pos].isspace():
                            pos += 1
                        if pos >= len(content):
                            break
                        try:
                            data, pos = decoder.raw_decode(content, pos)
                            if 'dominio' in data:
                                # Passa a conexão do banco para a função
                                ollama_filter(data['dominio'], conexao_banco)
                            time.sleep(20)
                        except json.JSONDecodeError as e:
                            print(f"[-] Erro ao decodificar pacote no log {file}: {e}")
                            break
    # Pausa antes de varrer a pasta novamente
    time.sleep(5)