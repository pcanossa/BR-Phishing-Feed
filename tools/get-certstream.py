import json
import certstream
import logging
import sys
import datetime
import os
import re
from collections import deque
from zmq import has

MARCAS_CURTAS = [
    'oi', 'tim', 'b3', 'cpf', 'vivo', 'uber', 'banco', 'cartao', 'gov-br'
]

# Marcas longas e específicas (Busca rápida)
MARCAS_LONGAS = [
    'correios', 'caixa', 'nubank', 'itau', 'bancodobrasil', 'receita', 
    'bradesco', 'santander', 'mercadolivre', 'magalu', 'americanas', 
    'detran', 'serasa', 'sicoob', 'c6bank', 'pagseguro', 'picpay', 
    'claro', 'netflix', 'spotify', 'loterias', 'debito', 'sedex', 'fazenda'
]

# Iscas de Engenharia Social
ISCAS = [
    'rastreio', 'taxa', 'promocao', 'seguranca', 'atualizacao', 'pagamento', 
    'app', 'login', 'desbloqueio', 'rastreamento', 'verificacao', 'confirmacao', 
    'alerta', 'bloqueio', 'senha', 'acesso', 'seguro', 'atencao', 'urgente', 
    'comprovante', 'boleto', 'fatura', 'cartao', 'debito', 'cpf', 'sus', 'gov-br', 'cnh', 'ipva', 'licenciamento', 'multas', 'infracao', 'recarga', 'transferencia', 'irpf', 'auxilio', 'freeflow', 'ganhar', 'premio', 'bonus', 'comprovante', 'trj', 'trt', 'federal', 'intimacao', 'processo',
    'justica'
    ]

# Domínios base permitidos (O .endswith já cobre subdomínios, ex: gov.br libera TUDO do governo)
WHITELIST = [
    'correios.com.br', 'gov.br', 'caixa.gov.br', 'nubank.com.br', 'itau.com.br', 
    'bb.com.br', 'bradesco.com.br', 'santander.com.br', 'mercadolivre.com.br', 
    'magalu.com.br', 'americanas.com.br', 'serasa.com.br', 'sicoob.com.br', 
    'c6bank.com.br', 'neon.com.br', 'next.com.br', 'pagseguro.uol.com.br', 
    'picpay.com', 'stone.com.br', 'vivo.com.br', 'claro.com.br', 'tim.com.br', 
    'oi.com.br', 'netflix.com', 'spotify.com', 'uber.com', 'ifood.com.br', 
    'bancopaulista.com.br', 'b3.com.br', 'pix.com.br', 'amazon.com.br', 'detran.sp.gov.br', 'loterias.caixa.gov.br', 'receita.fazenda.gov.br', 'bancodobrasil.com.br', 'serasaexperian.com.br', 'clarodigital.com.br', 'clarodigital.net', 'pagseguro.uol.com.br', '.adv', 'jus.br', 'org.br'
]
dominios_vistos = deque(maxlen=5000)

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

        # 1. Limpa duplicatas da mesma mensagem
        dominios_limpos = set()
        for domain in all_domains:
            dominios_limpos.add(domain.replace('*.', ''))

        # 2. Analisa a lista limpa
        for clean_domain in dominios_limpos:
            
            # SE O DOMÍNIO JÁ ESTIVER NA MEMÓRIA, PULA PARA O PRÓXIMO
            if clean_domain in dominios_vistos:
                continue
                
            # ADICIONA O NOVO DOMÍNIO NA MEMÓRIA
            dominios_vistos.append(clean_domain)

            # Faz a análise normal de Threat Intelligence
            suspeito, marcas_encontradas = is_suspicious(clean_domain)
            
            if suspeito:
                timestamp = datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')
                
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
                        f.flush()
                except Exception as e:
                    logging.error(f"Erro ao salvar no arquivo: {e}")
                 
print("Iniciando o monitoramento de certificados. Filtro de ameaças ativado...")
logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)


try:
    certstream.listen_for_events(print_callback, url='ws://127.0.0.1:8080/')
except Exception as e:
    logging.error(f"Conexão perdida: {e}. Reconectando em 5 segundos...")