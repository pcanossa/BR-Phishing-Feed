import os
import sqlite3
import re
import shutil

def gerenciar_logs_processados():
    logs_dir = "./logs"
    logs_malignos_dir = "./logs_filtrados" # Nova pasta de quarentena
    db_path = "./database/historico_cti.db"

    # Cria o diretório de malignos caso não exista
    if not os.path.exists(logs_malignos_dir):
        os.makedirs(logs_malignos_dir)
        print(f"[*] Diretório de quarentena '{logs_malignos_dir}' criado.")

    if not os.path.exists(logs_dir):
        print(f"[!] Diretório '{logs_dir}' não encontrado.")
        return

    if not os.path.exists(db_path):
        print(f"[!] Banco de dados '{db_path}' não encontrado.")
        return

    print("[*] Conectando ao banco de dados para buscar classificações...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Busca o domínio e o status de todos os registros
        cursor.execute("SELECT dominio, status FROM analises")
        resultados = cursor.fetchall()
        
        # Separa os domínios em dois sets para busca O(1) na memória
        benignos = {linha[0] for linha in resultados if linha[1] == 'benigno'}
        malignos = {linha[0] for linha in resultados if linha[1] == 'maligno'}
    except sqlite3.OperationalError as e:
        print(f"[!] Erro ao acessar o banco: {e}")
        conn.close()
        return

    conn.close()

    print(f"[*] {len(benignos)} domínios benignos e {len(malignos)} malignos encontrados no banco.")
    print(f"[*] Iniciando varredura e triagem na pasta '{logs_dir}'...\n")

    padrao = re.compile(r"^logs_(.*)_(\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2})\.json$")
    
    removidos = 0
    movidos = 0
    erros = 0

    for filename in os.listdir(logs_dir):
        if not filename.endswith('.json'):
            continue

        match = padrao.match(filename)
        if match:
            dominio_arquivo = match.group(1)
            filepath = os.path.join(logs_dir, filename)

            # Lógica 1: Se for lixo (benigno), deleta.
            if dominio_arquivo in benignos:
                try:
                    os.remove(filepath)
                    print(f"[-] DELETADO (Benigno): {filename}")
                    removidos += 1
                except Exception as e:
                    print(f"[!] Erro ao remover {filename}: {e}")
                    erros += 1
            
            # Lógica 2: Se for ameaça (maligno), move para a quarentena.
            elif dominio_arquivo in malignos:
                novo_filepath = os.path.join(logs_malignos_dir, filename)
                try:
                    shutil.move(filepath, novo_filepath)
                    print(f"[>] MOVIDO (Maligno): {filename} -> {logs_malignos_dir}")
                    movidos += 1
                except Exception as e:
                    print(f"[!] Erro ao mover {filename}: {e}")
                    erros += 1

    print("\n" + "="*50)
    print("RESUMO DA TRIAGEM DE LOGS:")
    print(f"Falsos positivos (Lixo) deletados: {removidos}")
    print(f"Arquivos Malignos isolados:        {movidos}")
    if erros > 0:
        print(f"Erros de I/O na operação:          {erros}")
    print("="*50)

if __name__ == "__main__":
    gerenciar_logs_processados()