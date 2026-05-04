import os
import re

def limpar_duplicatas_logs():
    # Caminho para a pasta de logs (ajuste se estiver rodando de outro diretório)
    log_dir = "../logs"
    
    # Regex para capturar o domínio do nome do arquivo
    # Exemplo: logs_13.creditodo.xyz_2026-05-03 18-48-34.json -> Grupo 1: 13.creditodo.xyz
    padrao = re.compile(r"^logs_(.*)_(\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2})\.json$")
    
    dominios_vistos = set()
    arquivos_removidos = 0
    arquivos_mantidos = 0

    if not os.path.exists(log_dir):
        print(f"[!] Diretório '{log_dir}' não encontrado.")
        return

    print("[*] Iniciando varredura e limpeza de duplicatas...\n")

    # sorted(..., reverse=True) garante que vamos ler os arquivos com datas mais recentes primeiro
    for filename in sorted(os.listdir(log_dir), reverse=True):
        match = padrao.match(filename)
        
        if match:
            dominio = match.group(1)
            filepath = os.path.join(log_dir, filename)

            # Se já vimos esse domínio (o mais recente), deletamos o atual (que é mais velho)
            if dominio in dominios_vistos:
                try:
                    os.remove(filepath)
                    print(f"[-] Duplicata removida: {filename}")
                    arquivos_removidos += 1
                except Exception as e:
                    print(f"[!] Erro ao remover {filename}: {e}")
            else:
                # É a primeira vez que vemos esse domínio (logo, é o arquivo mais novo dele)
                dominios_vistos.add(dominio)
                print(f"[+] Arquivo mantido: {filename}")
                arquivos_mantidos += 1

    print("\n" + "="*40)
    print("RESUMO DA FAXINA:")
    print(f"Domínios únicos mantidos: {arquivos_mantidos}")
    print(f"Duplicatas deletadas: {arquivos_removidos}")
    print("="*40)

if __name__ == "__main__":
    # Boa prática: faça um backup da pasta ./logs antes de rodar, só por segurança.
    limpar_duplicatas_logs()