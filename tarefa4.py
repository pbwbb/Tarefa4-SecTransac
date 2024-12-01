#pip install cryptography
#as outras libs devem vir como padrâo com o python

import hashlib
import os
import ssl
import base64
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

ac_raiz_confiaveis = set()

def extrair_nome_formatado(nome):
    partes = []
    for atributo in nome:
        if atributo.oid._name in ["commonName", "organizationName", "countryName"]:
            partes.append(f"{atributo.oid._name}: {atributo.value}")
    return ", ".join(partes)

def imprimir_informacoes_certificado(certificado):
    print("\nInformações do Certificado:")
    print(f" - Subject: {extrair_nome_formatado(certificado.subject)}")
    print(f" - Issuer: {extrair_nome_formatado(certificado.issuer)}")
    print(f" - Número de série: {certificado.serial_number}")
    print(f" - Válido de: {certificado.not_valid_before_utc}")
    print(f" - Válido até: {certificado.not_valid_after_utc}")
    print(f" - Versão: {certificado.version}")
    print(f" - Algoritmo de Assinatura: {certificado.signature_algorithm_oid._name}")
    print("\nExtensões:")
    print("-" * 40 + "\n")
    for ext in certificado.extensions:
        print(f" - {ext.oid._name}: {ext.value}")
    print("-" * 40 + "\n")

def adicionar_ac_raiz():
    caminho_ac = input("Informe o caminho para o certificado da AC-Raiz confiável (arquivo .pem, .cer ou .crt): ")
    print("-" * 40 + "\n")
    print("-" * 40 + "\n")
    if os.path.isfile(caminho_ac):
        try:
            with open(caminho_ac, "rb") as f:
                certificado = x509.load_pem_x509_certificate(f.read())
                skid_extension = certificado.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
                skid_ac_raiz = skid_extension.value
                skid_bytes = bytes(skid_ac_raiz.digest)
                skid_base64 = base64.b64encode(skid_bytes).decode('utf-8')
                imprimir_informacoes_certificado(certificado)
                print(f"Subject key Identifier: {skid_base64}")
                ac_raiz_confiaveis.add(skid_base64)
                print("AC-Raiz adicionada com sucesso.\n")
                print("-" * 40 + "\n")
                print(f"ACs Confiáveis: ")
                for ac in ac_raiz_confiaveis:
                    print(ac)
                print("-" * 40 + "\n")
        except Exception as e:
            print(f"Erro ao processar o arquivo: {e}")
    else:
        print("Arquivo não encontrado.")


def comparar_ac_raiz_com_skid(certificado, conteiner_ac_raiz):
    try:
        skid_extension = certificado.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
        skid_ac = skid_extension.value
        skid_bytes = skid_ac.digest
        skid_base64 = base64.b64encode(skid_bytes).decode('utf-8')
        if skid_base64 in conteiner_ac_raiz:
            print(f"Certificado confiável: {skid_base64}")
            print(f" - Subject: {extrair_nome_formatado(certificado.subject)}")
            return True
        else:
            print(f"Certificado não confiável. SKID {skid_base64} não encontrado.")
            return False
    except x509.ExtensionNotFound:
        print("Certificado não contém a extensão Subject Key Identifier (SKID) ou AKID.")
        return False


def verificar_certificado():
    caminho_certificado = input("Informe o caminho para o certificado contendo a cadeia de certificação (arquivo .pem, .cer ou .crt): ")    
    if os.path.isfile(caminho_certificado):
        try:
            with open(caminho_certificado, "rb") as f:
                cert_bytes = f.read()
                
                certificados = cert_bytes.split(b"-----END CERTIFICATE-----")
                cert_chain = []
                for cert in certificados:
                    cert = cert.strip()
                    if cert:
                        cert += b"-----END CERTIFICATE-----"  
                        certificado = x509.load_pem_x509_certificate(cert, default_backend())
                        cert_chain.append(certificado)
                print("-" * 40 + "\n")
                print("-" * 40 + "\n")
                for index, certificado in enumerate(cert_chain, start=1):
                    print(f"certificado {index}")
                    imprimir_informacoes_certificado(certificado)
                for cert in cert_chain:
                    cert = certificado
                comparar_ac_raiz_com_skid(certificado, ac_raiz_confiaveis)

        except Exception as e:
            print(f"Erro ao processar o arquivo: {e}")
    else:
        print("Arquivo de certificado não encontrado.")
    
 
def main():
    
    while True:
        print("\nMenu:")
        print("1. Adicionar uma AC-Raiz confiável")
        print("2. Selecionar um certificado digital para verificar")
        print("3. Visualizar ACs confiáveis")
        print("4. Sair")
        print("-" * 40 + "\n")  
        escolha = input("Escolha uma opção: ")
        if escolha == "1":
            adicionar_ac_raiz()
        elif escolha == "2":
            verificar_certificado()
        elif escolha == "3":
            for ac in ac_raiz_confiaveis:
                print("ACs confiáveis:")
                print(ac)
                print("-" * 40 + "\n")
        elif escolha == "4":
            print("Saindo...")
            break
        else:
            print("Escolha inválida. Tente novamente.")

if __name__ == "__main__":
    main()
