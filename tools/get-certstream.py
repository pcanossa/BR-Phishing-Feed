import json
import certstream
import logging
import sys
import datetime
import os
import re

from zmq import has

MARCAS_CURTAS = [
    'oi', 'tim', 'sus', 'gov', 'b3', 'pix', 'cpf', 'neon', 'next', 
    'vivo', 'uber', 'stone', 'banco', 'cartao', 'gov-br'
]

# Marcas longas e específicas (Busca rápida)
MARCAS_LONGAS = [
    'correios', 'caixa', 'nubank', 'itau', 'bancodobrasil', 'receita', 
    'bradesco', 'santander', 'mercadolivre', 'magalu', 'americanas', 
    'detran', 'serasa', 'sicoob', 'c6bank', 'pagseguro', 'picpay', 
    'claro', 'netflix', 'spotify', 'ifood', 'loterias', 'credito', 'debito', 'sedex', 'amazon', 'fazenda', 'irpf'
]

# Iscas de Engenharia Social
ISCAS = [
    'rastreio', 'taxa', 'promocao', 'seguranca', 'atualizacao', 'pagamento', 
    'app', 'login', 'desbloqueio', 'rastreamento', 'verificacao', 'confirmacao', 
    'alerta', 'bloqueio', 'senha', 'acesso', 'seguro', 'atencao', 'urgente', 
    'comprovante', 'boleto', 'fatura', 'cartao', 'credito', 'debito', 'cpf', 'sus', 'gov-br'
]

# Domínios base permitidos (O .endswith já cobre subdomínios, ex: gov.br libera TUDO do governo)
WHITELIST = [
    'correios.com.br', 'gov.br', 'caixa.gov.br', 'nubank.com.br', 'itau.com.br', 
    'bb.com.br', 'bradesco.com.br', 'santander.com.br', 'mercadolivre.com.br', 
    'magalu.com.br', 'americanas.com.br', 'serasa.com.br', 'sicoob.com.br', 
    'c6bank.com.br', 'neon.com.br', 'next.com.br', 'pagseguro.uol.com.br', 
    'picpay.com', 'stone.com.br', 'vivo.com.br', 'claro.com.br', 'tim.com.br', 
    'oi.com.br', 'netflix.com', 'spotify.com', 'uber.com', 'ifood.com.br', 
    'bancopaulista.com.br', 'b3.com.br', 'pix.com.br', 'amazon.com.br', 'detran.sp.gov.br', 'loterias.caixa.gov.br', 'receita.fazenda.gov.br', 'bancodobrasil.com.br']

def is_suspicious(domain):
    domain_lower = domain.lower()
    
    # 1. Checagem de Whitelist
    # Exige que o domínio termine exatamente com o domínio da whitelist, 
    # precedido de um ponto (para evitar que 'falsonubank.com.br' passe na whitelist)
    # ou que seja o domínio exato.
    for wl in WHITELIST:
        if domain_lower == wl or domain_lower.endswith(f".{wl}"):
            return False, []

    marcas_detectadas = []

    # 2. Regex para Marcas Curtas
    for marca in MARCAS_CURTAS:
        padrao = rf"(?:^|\.|-){marca}(?:\.|-|$)"
        if re.search(padrao, domain_lower):
            marcas_detectadas.append(marca)

    # 3. Busca Ampla para Marcas Longas
    for marca in MARCAS_LONGAS:
        if marca in domain_lower:
            marcas_detectadas.append(marca)
    
    # 4. Checagem de Iscas
    iscas_detectadas = [isca for isca in ISCAS if isca in domain_lower]
    
    # Validação Final (Exige 1 Marca + 1 Isca para ser um alerta)
    if marcas_detectadas and iscas_detectadas:
        return True, marcas_detectadas
    
    return False, []

def print_callback(message, context):
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            # Remove o prefixo wildcard (*.) para limpar a string de análise
            clean_domain = domain.replace('*.', '')
            
            # CORREÇÃO: Desempacotando as variáveis corretamente
            suspeito, marcas_encontradas = is_suspicious(clean_domain)
            
            # If avalia apenas o Booleano (True/False)
            if suspeito:
                timestamp = datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')
                
                # Formata a saída no terminal destacando o achado e as marcas
                sys.stdout.write(f"[ALERTA] {timestamp} - Phishing Detectado: {clean_domain} | Marca(s): {marcas_encontradas}\n")
                sys.stdout.flush()
                
                json_dominio = {
                    "dominio": clean_domain,
                    "marcas_encontradas": marcas_encontradas,
                    "timestamp": timestamp,
                    "dados_certificado": message['data']
                }

                # Salva no arquivo de log
                try:
                    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    log_dir = os.path.join(project_root, 'logs')
                    os.makedirs(log_dir, exist_ok=True)
                    log_path = os.path.join(log_dir, f'logs_{clean_domain}_{datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")}.json')
                    
                    with open(log_path, 'a', encoding='utf-8') as f:
                        json.dump(json_dominio, f, indent=2)
                        # Força o S.O. a despejar a memória no arquivo físico na mesma hora
                        f.flush()
                except Exception as e:
                    logging.error(f"Erro ao salvar no arquivo: {e}")
                 
print("Iniciando o monitoramento de certificados. Filtro de ameaças ativado...")
logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)


try:
    certstream.listen_for_events(print_callback, url='ws://127.0.0.1:8080/')
except Exception as e:
    logging.error(f"Conexão perdida: {e}. Reconectando em 5 segundos...")