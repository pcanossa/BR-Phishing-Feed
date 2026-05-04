import os
import sqlite3
import re

def limpar_logs_benignos():
    logs_dir = "../logs"
    db_path = "../database/historico_cti.db"

    if not os.path.exists(logs_dir):
        print(f"[!] Diretório '{logs_dir}' não encontrado.")
        return

    if not os.path.exists(db_path):
        print(f"[!] Banco de dados '{db_path}' não encontrado. Execute o analisador primeiro.")
        return

    print("[*] Conectando ao banco de dados para buscar domínios benignos...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Busca apenas os domínios classificados como benignos (falsos positivos)
        cursor.execute("SELECT dominio FROM analises WHERE status = 'benigno'")
        # Usa um set comprehension para criar uma lista de busca ultrarrápida na memória
        benignos = {linha[0] for linha in cursor.fetchall()}
    except sqlite3.OperationalError as e:
        print(f"[!] Erro ao acessar o banco. A tabela existe? {e}")
        conn.close()
        return

    conn.close()

    print(f"[*] {len(benignos)} domínios benignos encontrados no banco de dados.")
    print(f"[*] Iniciando varredura na pasta '{logs_dir}'...\n")

    # Regex para extrair o domínio do nome do arquivo bruto do CertStream
    # Exemplo: logs_bancodobrasil.com.br_2026-05-04 12-00-18.json -> Grupo 1: bancodobrasil.com.br
    padrao = re.compile(r"^logs_(.*)_(\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2})\.json$")
    
    removidos = 0
    erros = 0

    for filename in os.listdir(logs_dir):
        if not filename.endswith('.json'):
            continue

        match = padrao.match(filename)
        if match:
            dominio_arquivo = match.group(1)

            # Se o domínio do arquivo bruto estiver na nossa lista de benignos do banco, é lixo.
            if dominio_arquivo in benignos:
                filepath = os.path.join(logs_dir, filename)
                try:
                    os.remove(filepath)
                    print(f"[-] DELETADO (Benigno Confirmado): {filename}")
                    removidos += 1
                except Exception as e:
                    print(f"[!] Erro ao remover {filename}: {e}")
                    erros += 1

    print("\n" + "="*50)
    print("RESUMO DA HIGIENIZAÇÃO DA PASTA DE LOGS:")
    print(f"Arquivos brutos de falsos positivos deletados: {removidos}")
    if erros > 0:
        print(f"Erros de exclusão: {erros}")
    print("="*50)

if __name__ == "__main__":
    limpar_logs_benignos()