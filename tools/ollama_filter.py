import os
import sys
from time import time

# Adiciona o diretório raiz do projeto ao path do Python para encontrar a pasta 'prompts'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ollama_engine import ollama_engine
from prompts.filter_phish import generate_phishing_prompt as phishing_prompt
import json
import datetime

#

def ollama_filter(dominio):

    prompt = phishing_prompt()

    final_message = [
        {
            'role': 'system',
            'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts e comportamentos maliciosos.'
        },
        {
            'role': 'user',
            'content': prompt
        },
        {
          'role': 'user',
          'content': dominio
        }
    ] 

    report_filename = f"{dominio}.json"
    report_path = f"./phishing_domain_feed/{report_filename}"

    # Garante que a pasta de relatórios exista antes de escrever arquivos nela
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    if os.path.exists(report_path):
        print(f"[+] Domínio '{dominio}' já analisado. Relatório existente: {report_path}")
        return

    print(f"[+] Domínio '{dominio}' ainda não analisado. Gerando novo relatório...")
    while True:
        try:
            # Tenta se comunicar com a IA
            full_response = ollama_engine(message=final_message)
            
            # Se deu certo e não teve erro, o break quebra o 'while' e o código continua para o JSON lá embaixo
            break 
            
        except Exception as e:
            print(f"\n[!] Erro ao comunicar com o modelo de IA (Rate Limit/Timeout): {e}")
            print(f"[*] A API bloqueou. Aguardando 5 minutos antes de tentar o domínio '{dominio}' novamente...")
            
            # Dorme por 5 minutos (300 segundos). O tempo todo que o script ficar parado aqui, 
            # os novos domínios do CertStream continuam se acumulando com segurança na pasta /logs.
            import time
            time.sleep(300) 
            
            print("[*] Fim da pausa. Tentando reconectar...")
    try:
        # Extrai de forma segura o JSON do texto, caso o modelo inclua formatação Markdown ou texto extra
        json_str = full_response.strip()
        start_idx = json_str.find('{')
        end_idx = json_str.rfind('}')
        
        if start_idx != -1 and end_idx != -1:
            json_str = json_str[start_idx:end_idx+1]
            
        response_json = json.loads(json_str)
        
        if response_json.get("categoria_ameaca") == "false" or response_json.get("categoria_ameaca") == False or response_json.get("categoria_ameaza") == "false" or response_json.get("categoria_ameaza") == False:
            print(f"[!] Domínio '{dominio}' identificado como não maligno.")
            return
            
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(response_json, f, indent=4, ensure_ascii=False)
    except json.JSONDecodeError as e:
        print(f"[-] Erro ao fazer o parse do JSON do LLM: {e}. Salvando formato bruto...")
        # Se o modelo gerou algo fora do padrão JSON, salvamos apenas como texto plano
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(full_response)
            
    print(f"[+] Relatório salvo em: {report_path}")


while True:

    for file in os.listdir("./logs"):
        if file.endswith(".json"):
            with open(f"./logs/{file}", "r", encoding="utf-8") as f:
                content = f.read()

                decoder = json.JSONDecoder()
                pos = 0

                # Faz a varredura lendo quantos JSONs existirem dentro do mesmo arquivo
                while pos < len(content):
                    while pos < len(content) and content[pos].isspace():
                        pos += 1
                    if pos >= len(content):
                        break
                    try:
                        data, pos = decoder.raw_decode(content, pos)
                        if 'dominio' in data:
                            ollama_filter(data['dominio'])
                            time.sleep(5)
                    except json.JSONDecodeError as e:
                        print(f"[-] Erro ao decodificar pacote JSON no arquivo {file}: {e}")
                        break