from scapy.all import rdpcap, TCP, Raw
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json

PCAP      = "transacciones_cifradas.pcap"
CLAVE_RSA = "clave_privada.pem"


print("--- 1. Leyendo el pcap ---")
pkts = rdpcap(PCAP)
payloads = [bytes(p[Raw].load) for p in pkts if TCP in p and Raw in p]

print("--- 2. Buscando RSA_PIN ---")
rsa_pkt = next((pl for pl in payloads if pl.startswith(b"RSA_PIN")), None)
if rsa_pkt is None:
    raise SystemExit("No se encontró RSA_PIN")

OFFSET_SALT = 9
salt       = rsa_pkt[OFFSET_SALT:OFFSET_SALT+16]
ciphertext = rsa_pkt[OFFSET_SALT+16:]
print(f"Salt (hex): {salt.hex()}")

print("\n--- 3. Cargando clave RSA y recuperando PIN ---")
with open(CLAVE_RSA, "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)

pin = priv.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None),
)
print(f"PIN recuperado: {pin!r}")

print("\n--- 4. Derivando clave AES con scrypt ---")
N = 2**14
r = 8
p = 1
key = Scrypt(salt=salt, length=32, n=N, r=r, p=p).derive(pin)
print(f"Parámetros scrypt: N=2^14, r=8, p=1")
print(f"Clave AES (32 bytes, hex): {key.hex()}")

print("\n--- 5. Descifrando mensajes AESGCM ---")
aesgcm = AESGCM(key)
NONCE_LEN = 12
TAG_LEN   = 16

ok = 0
total = 0

for pl in payloads:
    if not pl.startswith(b"AESGCM"):
        continue
    total += 1
    
    # OJO: Recuerda el carácter '|' que vimos en Wireshark.
    # Si al correrlo da error, cambia el pl[6:] por pl[7:]
    body = pl[7:] 
    
    nonce = body[:NONCE_LEN]
    resto = body[NONCE_LEN:]
    ct  = resto[:-TAG_LEN]
    tag = resto[-TAG_LEN:]

    try:
        plain = aesgcm.decrypt(nonce, ct + tag, None)
        ok += 1
        try:
            d = json.loads(plain)
            print(f"[OK #{total}] id={d.get('id')} de={d.get('remitente')} a={d.get('destinatario')} monto={d.get('monto')} nonce={nonce.hex()}")
        except json.JSONDecodeError:
            print(f"[OK #{total}] nonce={nonce.hex()} -> {plain.decode(errors='replace')}")
    except Exception as e:
        print(f"[FAIL #{total}] nonce={nonce.hex()} -> {type(e).__name__}: {e}")

print(f"\n  Mensajes autenticados: {ok} de {total}")
