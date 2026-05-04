import os
import json
import sqlite3
import datetime

def varredura_forca_bruta():
    feed_dir = "../phishing_domain_feed"
    db_path = "../database/historico_cti.db"

    print("[*] Iniciando varredura de Força Bruta nos arquivos restantes...\n")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # A PEÇA QUE FALTAVA: Garante que a tabela existe, não importa de onde o script seja rodado
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analises (
            dominio TEXT PRIMARY KEY,
            status TEXT,
            data_analise TEXT
        )
    ''')

    arquivos = [f for f in os.listdir(feed_dir) if f.endswith('.json')]
    
    removidos = 0
    erros_reais = 0

    for filename in arquivos:
        filepath = os.path.join(feed_dir, filename)
        dominio = filename.replace('.json', '')
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                conteudo = f.read()
            
            # IGNORA O MARKDOWN: Procura a primeira chave '{' e a última '}' e corta o resto
            start_idx = conteudo.find('{')
            end_idx = conteudo.rfind('}')
            
            if start_idx != -1 and end_idx != -1:
                json_limpo = conteudo[start_idx:end_idx+1]
                
                try:
                    dados = json.loads(json_limpo)
                    categoria = str(dados.get("categoria_ameaca", "")).lower()
                    data_atual = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    if categoria == "false":
                        status = "benigno"
                        
                        # Insere no banco
                        cursor.execute('''
                            INSERT OR IGNORE INTO analises (dominio, status, data_analise) 
                            VALUES (?, ?, ?)
                        ''', (dominio, status, data_atual))
                        
                        # APAGA O ARQUIVO FÍSICO
                        os.remove(filepath)
                        removidos += 1
                        print(f"[-] DELETADO: '{filename}' (Falso positivo identificado e cacheado)")
                    
                    else:
                        # Se for maligno, nós só garantimos que está no banco e deixamos o arquivo quieto
                        cursor.execute('''
                            INSERT OR IGNORE INTO analises (dominio, status, data_analise) 
                            VALUES (?, ?, ?)
                        ''', (dominio, "maligno", data_atual))

                except json.JSONDecodeError:
                    print(f"[!] Arquivo irrecuperável (não é JSON válido): {filename}")
                    erros_reais += 1
            else:
                print(f"[!] Nenhuma estrutura JSON encontrada em: {filename}")
                erros_reais += 1

        except Exception as e:
            print(f"[!] Erro de sistema no arquivo {filename}: {e}")

    conn.commit()
    conn.close()

    print("\n" + "="*50)
    print("RESUMO DA LIMPEZA BRUTA:")
    print(f"Falsos positivos pulverizados do disco: {removidos}")
    print(f"Arquivos completamente corrompidos (lixo): {erros_reais}")
    print("="*50)

if __name__ == "__main__":
    varredura_forca_bruta()