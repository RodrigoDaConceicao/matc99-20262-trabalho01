#!/usr/bin/env python
"""
MATC99 - Segurança e Auditoria de Sistemas de Informação
Trabalho 01 - Criptografia Aplicada — Parte I
Proteção e Integridade de Documentos com AES-GCM

Experimentos realizados:
  1. Criação de um documento comercial fictício (.txt);
  2. Criptografia com AES-256-GCM (nonce de 96 bits + tag de 128 bits);
  3. Descriptografia com a chave correta (sucesso);
  4. Descriptografia com ciphertext adulterado (falha de autenticação);
  5. Descriptografia com chave incorreta (falha de autenticação).

Uso:  py scripts\\parte1_aes_gcm.py
Bibliotecas: cryptography (https://pypi.org/project/cryptography/)
"""

import secrets
import sys
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = Path(__file__).resolve().parent.parent
DOC_DIR = BASE / "documentos"
KEY_DIR = BASE / "chaves" / "aes"
ENC_DIR = BASE / "criptografia"
EVID_DIR = BASE / "evidencias"

# ---------------------------------------------------------------------------
# 1. Documento comercial fictício
# ---------------------------------------------------------------------------
DOCUMENTO_COMERCIAL = """CONTRATO DE PRESTAÇÃO DE SERVIÇOS DE TECNOLOGIA
================================================================

Contrato nº 2026-0147 — XYZW Tecnologia S.A. / Cliente Fictício Ltda.

1. PARTES
   CONTRATADA: XYZW Tecnologia S.A., CNPJ 12.345.678/0001-90, com sede
   em São Paulo/SP.
   CONTRATANTE: Cliente Fictício Ltda., CNPJ 98.765.432/0001-10, com
   sede em Belo Horizonte/MG.

2. OBJETO
   A prestação de serviços de desenvolvimento, implantação e
   manutenção de sistemas de informação, incluindo suporte técnico
   remoto e on-site, no período de 12 (doze) meses.

3. VALOR E CONDIÇÕES DE PAGAMENTO
   O valor total do contrato é de R$ 480.000,00 (quatrocentos e
   oitenta mil reais), pagável em 12 parcelas mensais de R$ 40.000,00,
   vencidas no dia 10 de cada mês.

4. NÍVEL DE SERVIÇO (SLA)
   Disponibilidade mínima de 99,5% para os sistemas críticos, com
   multa de 1% do valor mensal por ponto percentual de indisponibilidade
   não atendida.

5. PROTEÇÃO DE DADOS E CONFIDENCIALIDADE
   As partes se obrigam a manter sigilo sobre informações comerciais e
   a tratar dados pessoais em conformidade com a LGPD (Lei nº
   13.709/2018).

6. VIGÊNCIA
   Este contrato vigorará por 12 (doze) meses, contados da assinatura,
   podendo ser prorrogado por mútuo acordo.

Assinam o presente instrumento em duas vias de igual teor e forma.

São Paulo/SP, 10 de outubro de 2026.

__________________________________
XYZW Tecnologia S.A.

__________________________________
Cliente Fictício Ltda.
"""


def linha_sep() -> str:
    return "-" * 72


def main() -> None:
    DOC_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    ENC_DIR.mkdir(parents=True, exist_ok=True)
    EVID_DIR.mkdir(parents=True, exist_ok=True)

    evidencias: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        evidencias.append(msg)

    log(linha_sep())
    log("MATC99 - TRABALHO 01 - PARTE I: CRIPTOGRAFIA AES-GCM")
    log(f"Executado em: {datetime.now():%d/%m/%Y %H:%M:%S}")
    log(linha_sep())

    # ------------------------------------------------------------------
    # Passo 1 — documento fictício
    # ------------------------------------------------------------------
    doc_path = DOC_DIR / "contrato_comercial.txt"
    doc_path.write_bytes(DOCUMENTO_COMERCIAL.encode("utf-8"))
    plaintext = doc_path.read_bytes()
    log(f"\n[1] Documento criado: {doc_path.name} ({len(plaintext)} bytes).")

    # ------------------------------------------------------------------
    # Passo 2 — criptografia AES-256-GCM
    # ------------------------------------------------------------------
    key = AESGCM.generate_key(bit_length=256)   # chave aleatória de 256 bits
    nonce = secrets.token_bytes(12)             # nonce de 96 bits (padrão AES-GCM)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)  # ct || tag(16 B)

    key_path = KEY_DIR / "chave_aes_gcm.key"
    key_path.write_text(key.hex() + "\n")
    enc_path = ENC_DIR / "contrato_comercial.gcm"
    enc_path.write_bytes(nonce + ciphertext)

    log(f"[2] Chave AES-256 gerada e salva em: chaves/aes/chave_aes_gcm.key")
    log(f"    Chave (hex): {key.hex()}")
    log(f"    Nonce (hex): {nonce.hex()}")
    log(f"[3] Ciphertext gerado: {enc_path.name}")
    log(f"    Formato do arquivo: [nonce 12 B][ciphertext][tag 16 B]")
    log(f"    Tamanho do ciphertext+tag: {len(ciphertext)} bytes")
    log(f"    Início do ciphertext (hex): {ciphertext[:24].hex()} ...")

    # ------------------------------------------------------------------
    # Passo 3 — descriptografia com a chave correta
    # ------------------------------------------------------------------
    log("\n[4] DESCRIPTOGRAFIA COM A CHAVE CORRETA")
    data = enc_path.read_bytes()
    n, c = data[:12], data[12:]
    plaintext_ok = AESGCM(key).decrypt(n, c, None)
    ok = plaintext_ok == plaintext
    (ENC_DIR / "contrato_comercial_descriptografado.txt").write_bytes(plaintext_ok)
    log(f"    Status: {'SUCESSO' if ok else 'FALHA'}")
    log(f"    Integridade do texto recuperado: {'idêntico ao original' if ok else 'DIVERGE'}")
    log(f"    Arquivo recuperado: criptografia/contrato_comercial_descriptografado.txt")

    # ------------------------------------------------------------------
    # Passo 4 — descriptografia com ciphertext ADULTERADO
    # ------------------------------------------------------------------
    log("\n[5] TESTE DE INTEGRIDADE: ciphertext com 1 bit alterado")
    c_alterado = bytearray(c)
    c_alterado[10] ^= 0x01  # inverte o bit 0 do byte 11 do ciphertext
    try:
        AESGCM(key).decrypt(n, bytes(c_alterado), None)
        log("    Status: SUCESSO (inesperado!)")
        tag_alterada_valida = False
    except InvalidTag as e:
        log(f"    Status: FALHA — InvalidTag ({type(e).__name__})")
        log("    A tag de autenticação não corresponde: adulteração detectada.")
        tag_alterada_valida = True

    # ------------------------------------------------------------------
    # Passo 5 — descriptografia com CHAVE INCORRETA
    # ------------------------------------------------------------------
    log("\n[6] TESTE DE AUTENTICAÇÃO: chave INCORRETA (aleatória, 256 bits)")
    wrong_key = AESGCM.generate_key(bit_length=256)
    log(f"    Chave incorreta (hex): {wrong_key.hex()}")
    try:
        AESGCM(wrong_key).decrypt(n, c, None)
        log("    Status: SUCESSO (inesperado!)")
        tag_chave_errada_valida = False
    except InvalidTag:
        log("    Status: FALHA — InvalidTag (InvalidTag)")
        log("    A chave não é a chave correta: autenticação do bloco falhou.")
        tag_chave_errada_valida = True

    log("\n" + linha_sep())
    log("RESUMO DOS RESULTADOS (PARTE I)")
    log(f"  Descriptografia com chave correta ........: SUCESSO")
    log(f"  Ciphertext adulterado (1 bit) ............: {'REJEITADO (InvalidTag)' if tag_alterada_valida else 'ACEITO (falha!)'}")
    log(f"  Chave incorreta ..........................: {'REJEITADO (InvalidTag)' if tag_chave_errada_valida else 'ACEITO (falha!)'}")
    log(linha_sep())

    evid_path = EVID_DIR / "resultado_parte1.txt"
    evid_path.write_text("\n".join(evidencias) + "\n", encoding="utf-8")
    print(f"\nEvidências salvas em: {evid_path}")


if __name__ == "__main__":
    main()
