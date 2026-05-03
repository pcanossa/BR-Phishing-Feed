from ollama import Client
import requests
import os
import sys

def ollama_engine(message):
    ollama_host = os.getenv('OLLAMA_HOST')
    if ollama_host and '0.0.0.0' in ollama_host:
        client = Client(host=ollama_host.replace('0.0.0.0', '127.0.0.1'))
    else:
        client = Client()

    try:
            full_response = []
            for part in client.chat('gpt-oss:120b-cloud', messages=message, stream=True):
              content = part['message']['content']
              full_response.append(content)
            return "".join(full_response)
    except Exception as e:
        print(f"\n\nErro ao comunicar com o modelo de IA: {e}")
        sys.exit(1)
