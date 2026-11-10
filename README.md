# MATC99 — Trabalho 01: Criptografia Aplicada (XYZW Tecnologia)

Reprodução dos experimentos de **proteção/integridade de documentos (AES-GCM)** e
**assinaturas digitais com certificados (PKI)** para a disciplina
*Segurança e Auditoria de Sistemas de Informação*.

> ⚠️ Ambiente de teste fictício. Todas as chaves, certificados e documentos
> gerados aqui pertencem ao exercício.

## Estrutura do repositório

```
trabalho-seguranca/
├── README.md                    # Instruções de reprodução (entregável D)
├── documentos/
│   ├── contrato_comercial.txt              # documento fictício original
│   └── contrato_comercial_alterado.txt     # documento adulterado (Caso B)
├── scripts/
│   ├── parte1_aes_gcm.py                 # Parte I (AES-GCM)
│   └── parte2_assinaturas_e_certificados.py  # Parte II (PKI/assinaturas)
├── chaves/
│   ├── aes/chave_aes_gcm.key             # chave AES-256 (hex)
│   ├── chave_pub_alpha.pem               # chave pública extraída do certificado
│   └── chave_pub_beta.pem                # chave pública extraída do certificado
├── criptografia/
│   ├── contrato_comercial.gcm            # [nonce 12B][ciphertext][tag 16B]
│   └── contrato_comercial_descriptografado.txt
├── certificados/
│   ├── ca_xyzw/                          # CA confiável (raiz do ambiente)
│   ├── ca_faketrust/                     # CA NÃO confiável
│   ├── parceiro_alpha/                   # certificado emitido pela CA XYZW
│   └── parceiro_beta/                    # certificado emitido pela FakeTrust
├── assinaturas/
│   ├── caso_A_contrato_original.sig
│   └── caso_C_contrato_para_beta.sig
└── evidencias/
    ├── resultado_parte1.txt
    ├── resultado_parte2.txt
    └── openssl_parte2.txt
```

## Pré-requisitos

| Ferramenta      | Versão testada | Instalação                                    |
|-----------------|----------------|---------------------------------------------|
| Python          | 3.14           | https://www.python.org (no Windows, o `py` launcher) |
| `cryptography`  | 48.0.1         | `pip install cryptography`                  |
| OpenSSL (opcional, para cross-check) | 3.6.3 | `pip install pyopenssl`                  |

```bash
pip install cryptography
```

## Execução

1. **Parte I — AES-GCM** (recria o documento, cifra, des cifra e roda os testes
   de adulteração e de chave incorreta):

   ```powershell
   py scripts\parte1_aes_gcm.py
   ```

2. **Parte II — Assinaturas e certificados** (gera as CAs, os certificados
   dos parceiros, assina os documentos e verifica os três cenários):

   ```powershell
   py scripts\parte2_assinaturas_e_certificados.py
   ```

   Cada execução re-gera chaves/certificados/assinaturas (os serial numbers e
   chaves mudam). Os resultados esperados são sempre:

   | Cenário | Assinatura | Cadeia | Decisão |
   |---------|-----------|--------|---------|
   | A — original, CA confiável | válida | válida | **aceitar** |
   | B — alterado após assinatura | **inválida** | válida | **rejeitar** |
   | C — CA não confiável | válida | **inválida** | **rejeitar** |

3. **Cross-check com OpenSSL (CLI)** — as mesmas verificações com ferramentas
   padrão:

   ```powershell
   # chave pública dos certificados
   openssl x509 -in certificados\parceiro_alpha\certificado_parceiro_alpha.pem -noout -pubkey -out chaves\chave_pub_alpha.pem
   openssl x509 -in certificados\parceiro_beta\certificado_parceiro_beta.pem -noout -pubkey -out chaves\chave_pub_beta.pem

   # Cadeia de certificação
   openssl verify -CAfile certificados\ca_xyzw\certificado_ca_xyzw.pem certificados\parceiro_alpha\certificado_parceiro_alpha.pem
   openssl verify -CAfile certificados\ca_xyzw\certificado_ca_xyzw.pem certificados\parceiro_beta\certificado_parceiro_beta.pem

   # Assinaturas digitais
   openssl dgst -sha256 -verify chaves\chave_pub_alpha.pem -signature assinaturas\caso_A_contrato_original.sig documentos\contrato_comercial.txt
   openssl dgst -sha256 -verify chaves\chave_pub_alpha.pem -signature assinaturas\caso_A_contrato_original.sig documentos\contrato_comercial_alterado.txt
   openssl dgst -sha256 -verify chaves\chave_pub_beta.pem  -signature assinaturas\caso_C_contrato_para_beta.sig documentos\contrato_comercial.txt
   ```

   As saídas reais estão em `evidencias/openssl_parte2.txt`.

## Observações

- O formato do arquivo cifrado é binário: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
- As chaves privadas ficam em `certificados/*/chave_*.pem` — em um ambiente
  real, elas jamais circulariam com os documentos.
- Os certificados e assinaturas usam **RSA 2048** com SHA-256 (PKCS#1 v1.5),
  validade 2026–2031 e data de referência da verificação = 09/11/2026.
