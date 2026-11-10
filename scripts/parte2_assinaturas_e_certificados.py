#!/usr/bin/env python
"""
MATC99 - Segurança e Auditoria de Sistemas de Informação
Trabalho 01 - Criptografia Aplicada — Parte II
Assinaturas Digitais e Certificados

Cenários reproduzidos:
  A — Documento original, assinado por parceiro confiável (CA confiável).
  B — Documento alterado APÓS a assinatura.
  C — Assinatura matematicamente válida, mas certificado emitido por
      CA não confiável (fora da cadeia de confiança).

Algoritmos: RSA 2048 + SHA-256, PKCS#1 v1.5 (assinaturas e certificados),
no mesmo padrão demonstrado em sala de aula.

Uso:  py scripts\\parte2_assinaturas_e_certificados.py
Bibliotecas: cryptography (https://pypi.org/project/cryptography/)
"""

from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.general_name import DNSName
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import (
    PolicyBuilder,
    Store,
    VerificationError,
)

BASE = Path(__file__).resolve().parent.parent
DOC_DIR = BASE / "documentos"
CERT_DIR = BASE / "certificados"
SIG_DIR = BASE / "assinaturas"
EVID_DIR = BASE / "evidencias"

DATA_VERIFICACAO = datetime(2026, 11, 9)  # data da entrega / auditoria
VALIDADE_INICIO = datetime(2026, 1, 1)
VALIDADE_FIM = datetime(2031, 1, 1)

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

# Adulteração simulada (Caso B): inserção de cláusula após a assinatura.
ADULTERACAO = (
    "\n7. CLÁUSULA ADICIONAL (INCLUIDA APÓS A ASSINATURA)\n"
    "   O CONTRATANTE concorda, de forma irrestrita e definitiva, em\n"
    "   ceder à CONTRATADA todos os direitos patrimoniais sobre dados,\n"
    "   marcas e produtos desenvolvidos, sem qualquer compensação."
    "\n"
)


def linha_sep() -> str:
    return "-" * 72


# ---------------------------------------------------------------------------
# Utilidades de PKI
# ---------------------------------------------------------------------------
def gerar_par_rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def salvar_pem(diretorio: Path, nome: str, objeto, private: bool = False, senha: str | None = None) -> None:
    diretorio.mkdir(parents=True, exist_ok=True)
    if private:
        fmt = serialization.PrivateFormat.PKCS8
        enc = serialization.BestAvailableEncryption(senha.encode()) if senha else serialization.NoEncryption()
        caminho = diretorio / nome
        caminho.write_bytes(objeto.private_bytes(serialization.Encoding.PEM, fmt, enc))
    else:
        caminho = diretorio / nome
        caminho.write_bytes(objeto.public_bytes(serialization.Encoding.PEM))


def emitir_certificado_ca(nome_cn: str, key: rsa.RSAPrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome_cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # autoassinado (raiz)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(VALIDADE_INICIO)
        .not_valid_after(VALIDADE_FIM)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )


def emitir_certificado_folha(
    nome_cn: str,
    key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    san_dns: str,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome_cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(VALIDADE_INICIO)
        .not_valid_after(VALIDADE_FIM)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName([DNSName(san_dns)]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )


def verificar_assinatura(doc: bytes, sig: bytes, pub) -> tuple[bool, str]:
    try:
        pub.verify(sig, doc, padding.PKCS1v15(), hashes.SHA256())
        return True, "assinatura VÁLIDA (RSA 2048 / SHA-256, PKCS#1 v1.5)"
    except Exception as e:  # cryptography.exceptions.InvalidSignature
        return False, f"assinatura INVÁLIDA ({type(e).__name__})"


def verificar_cadeia(cert: x509.Certificate, store: Store, san_dns: str) -> tuple[bool, str]:
    """Verifica a cadeia de certificação até a raiz confiável da loja.

    API de verificação X.509 da biblioteca cryptography (>= 47):
    Store + PolicyBuilder + ServerVerifier. Em caso de sucesso retorna a
    cadeia completa (lista de certificados); em caso de falha levanta
    VerificationError.
    """
    try:
        verifier = (
            PolicyBuilder()
            .store(store)
            .time(DATA_VERIFICACAO)
            .build_server_verifier(DNSName(san_dns))
        )
        cadeia = verifier.verify(cert, [])  # intermediates: sem CAs intermediárias
        return True, (
            f"cadeia VÁLIDA — {len(cadeia)} certificado(s) na cadeia; "
            f"raiz: {cadeia[-1].subject}"
        )
    except VerificationError as e:
        return False, f"cadeia INVÁLIDA — VerificationError: {e}"


def main() -> None:
    DOC_DIR.mkdir(parents=True, exist_ok=True)
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    SIG_DIR.mkdir(parents=True, exist_ok=True)
    EVID_DIR.mkdir(parents=True, exist_ok=True)

    evidencias: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        evidencias.append(msg)

    # Documento (reusado da Parte I se existir, senão recriado)
    doc_path = DOC_DIR / "contrato_comercial.txt"
    if not doc_path.exists():
        doc_path.write_bytes(DOCUMENTO_COMERCIAL.encode("utf-8"))
    original = doc_path.read_bytes()

    log(linha_sep())
    log("MATC99 - TRABALHO 01 - PARTE II: ASSINATURAS DIGITAIS E CERTIFICADOS")
    log(f"Data de referência da verificação: {DATA_VERIFICACAO:%d/%m/%Y}")
    log(linha_sep())

    # ------------------------------------------------------------------
    # Infraestrutura PKI
    # ------------------------------------------------------------------
    log("\n[A] INFRAESTRUTURA DE PKI (ambientes de teste autorizados)")

    # CA confiável (raiz do ambiente XYZW)
    ca_key = gerar_par_rsa()
    ca_cert = emitir_certificado_ca("Autoridade Certificadora XYZW Tecnologia S.A.", ca_key)
    salvar_pem(CERT_DIR / "ca_xyzw", "chave_ca_xyzw.pem", ca_key, private=True)
    salvar_pem(CERT_DIR / "ca_xyzw", "certificado_ca_xyzw.pem", ca_cert)
    log("  CA CONFIÁVEL gerada: 'Autoridade Certificadora XYZW Tecnologia S.A.' (RSA 2048, autoassinada, CA:TRUE)")

    # CA não confiável (fora da cadeia de confiança)
    fake_ca_key = gerar_par_rsa()
    fake_ca_cert = emitir_certificado_ca("Autoridade Certificadora FakeTrust Ltda.", fake_ca_key)
    salvar_pem(CERT_DIR / "ca_faketrust", "chave_ca_faketrust.pem", fake_ca_key, private=True)
    salvar_pem(CERT_DIR / "ca_faketrust", "certificado_ca_faketrust.pem", fake_ca_cert)
    log("  CA NÃO CONFIÁVEL gerada: 'Autoridade Certificadora FakeTrust Ltda.' (RSA 2048, autoassinada, CA:TRUE)")

    # Parceiro Alpha — certificado emitido pela CA confiável
    alpha_key = gerar_par_rsa()
    alpha_cert = emitir_certificado_folha(
        "Parceiro Alpha Ltda.", alpha_key, ca_cert, ca_key, san_dns="parceiro-alpha.xyzw.test"
    )
    salvar_pem(CERT_DIR / "parceiro_alpha", "chave_parceiro_alpha.pem", alpha_key, private=True)
    salvar_pem(CERT_DIR / "parceiro_alpha", "certificado_parceiro_alpha.pem", alpha_cert)
    log("  Certificado 'Parceiro Alpha Ltda.' emitido pela CA XYZW (confiável).")

    # Parceiro Beta — certificado emitido pela CA não confiável
    beta_key = gerar_par_rsa()
    beta_cert = emitir_certificado_folha(
        "Parceiro Beta Ltda.", beta_key, fake_ca_cert, fake_ca_key, san_dns="parceiro-beta.xyzw.test"
    )
    salvar_pem(CERT_DIR / "parceiro_beta", "chave_parceiro_beta.pem", beta_key, private=True)
    salvar_pem(CERT_DIR / "parceiro_beta", "certificado_parceiro_beta.pem", beta_cert)
    log("  Certificado 'Parceiro Beta Ltda.' emitido pela CA FakeTrust (NÃO confiável).")
    log(f"  Serial (CA XYZW)    : {ca_cert.serial_number}")
    log(f"  Serial (CA FakeTrust): {fake_ca_cert.serial_number}")
    log(f"  Serial (Alpha)       : {alpha_cert.serial_number}")
    log(f"  Serial (Beta)        : {beta_cert.serial_number}")

    store_confiavel = Store([ca_cert])  # loja de confiança: apenas a CA XYZW

    # ------------------------------------------------------------------
    # CASO A — documento original, assinado corretamente, CA confiável
    # ------------------------------------------------------------------
    log("\n" + linha_sep())
    log("CASO A — documento original, assinatura correta, certificado confiável")
    sig_a = alpha_key.sign(original, padding.PKCS1v15(), hashes.SHA256())
    (SIG_DIR / "caso_A_contrato_original.sig").write_bytes(sig_a)
    ok_sig_a, msg_sig_a = verificar_assinatura(original, sig_a, alpha_cert.public_key())
    ok_chain_a, msg_chain_a = verificar_cadeia(alpha_cert, store_confiavel, "parceiro-alpha.xyzw.test")
    log(f"  Assinatura  : {msg_sig_a}")
    log(f"  Cadeia      : {msg_chain_a}")
    log("  DECISÃO     : ACEITAR — autenticidade, integridade e origem confiáveis.")

    # ------------------------------------------------------------------
    # CASO B — documento alterado APÓS a assinatura
    # ------------------------------------------------------------------
    log("\n" + linha_sep())
    log("CASO B — documento alterado após a assinatura")
    adulterado = original + ADULTERACAO.encode("utf-8")
    (DOC_DIR / "contrato_comercial_alterado.txt").write_bytes(adulterado)
    log("  Adulteração simulada: inserida a 'CLÁUSULA ADICIONAL' após a assinatura.")
    log(f"  (Assinatura reutilizada do Caso A sobre o documento ORIGINAL)")
    ok_sig_b, msg_sig_b = verificar_assinatura(adulterado, sig_a, alpha_cert.public_key())
    ok_chain_b, msg_chain_b = verificar_cadeia(alpha_cert, store_confiavel, "parceiro-alpha.xyzw.test")
    log(f"  Assinatura  : {msg_sig_b}")
    log(f"  Cadeia      : {msg_chain_b}")
    log("  DECISÃO     : REJEITAR — assinatura não cobre o documento apresentado.")

    # ------------------------------------------------------------------
    # CASO C — assinatura válida matematicamente, CA não confiável
    # ------------------------------------------------------------------
    log("\n" + linha_sep())
    log("CASO C — assinatura válida, certificado emitido por CA NÃO confiável")
    sig_c = beta_key.sign(original, padding.PKCS1v15(), hashes.SHA256())
    (SIG_DIR / "caso_C_contrato_para_beta.sig").write_bytes(sig_c)
    ok_sig_c, msg_sig_c = verificar_assinatura(original, sig_c, beta_cert.public_key())
    ok_chain_c, msg_chain_c = verificar_cadeia(beta_cert, store_confiavel, "parceiro-beta.xyzw.test")
    # Controle: a cadeia do Beta seria válida se a FakeTrust fosse confiável?
    store_fake = Store([fake_ca_cert])
    ok_chain_c_fake, msg_chain_c_fake = verificar_cadeia(beta_cert, store_fake, "parceiro-beta.xyzw.test")
    log(f"  Assinatura (chave pública do certificado)   : {msg_sig_c}")
    log(f"  Cadeia contra store da CA XYZW (confiável)  : {msg_chain_c}")
    log(f"  Controle: cadeia contra store da FakeTrust  : {msg_chain_c_fake}")
    log("  DECISÃO     : REJEITAR — a assinatura é matematicamente válida, mas o")
    log("                certificado não se ancora em CA confiável: não é possível")
    log("                confiar na identidade do signatário.")

    # ------------------------------------------------------------------
    # Resumo
    # ------------------------------------------------------------------
    log("\n" + linha_sep())
    log("RESUMO DOS RESULTADOS (PARTE II)")
    log(f"  CASO A: assinatura {'OK' if ok_sig_a else 'FALHA'} | cadeia {'OK' if ok_chain_a else 'FALHA'} | DECISÃO: ACEITAR")
    log(f"  CASO B: assinatura {'OK' if ok_sig_b else 'FALHA'} | cadeia {'OK' if ok_chain_b else 'FALHA'} | DECISÃO: REJEITAR")
    log(f"  CASO C: assinatura {'OK' if ok_sig_c else 'FALHA'} | cadeia {'OK' if ok_chain_c else 'FALHA'} | DECISÃO: REJEITAR")
    log(linha_sep())

    evid_path = EVID_DIR / "resultado_parte2.txt"
    evid_path.write_text("\n".join(evidencias) + "\n", encoding="utf-8")
    print(f"\nEvidências salvas em: {evid_path}")


if __name__ == "__main__":
    main()
