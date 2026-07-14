"""
PQC Demo: ML-KEM-768 Key Exchange + ML-DSA-65 Digital Signature
=================================================================
Demo pratico di crittografia post-quantistica basato sugli standard
NIST FIPS 203 (ML-KEM) e FIPS 204 (ML-DSA), tramite la libreria
`pqcrypto` (Python bindings per PQClean, la reference implementation
citata anche in molti annunci per ruoli di Cryptography Engineer).

Requisiti:
    pip install pqcrypto

Uso:
    python mlkem_demo.py
"""

from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt
from pqcrypto.sign.ml_dsa_65 import generate_keypair as dsa_generate_keypair
from pqcrypto.sign.ml_dsa_65 import sign, verify


# ============================================
# PARTE 1: Key Exchange con ML-KEM-768
# ============================================
print("=== ML-KEM-768 Key Exchange Demo ===\n")

# --- Lato SERVER ---
# Il server genera una coppia di chiavi: pubblica e privata.
# La sicurezza si basa sul problema Module-LWE (Learning With Errors
# su reticoli strutturati), ritenuto difficile anche per computer
# quantistici (a differenza di RSA/ECC, vulnerabili all'algoritmo di Shor).
print("[Server] Genero coppia di chiavi ML-KEM-768...")
public_key, secret_key = generate_keypair()
print(f"[Server] Chiave pubblica generata ({len(public_key)} byte)")
print(f"[Server] Chiave segreta generata ({len(secret_key)} byte)\n")

# Il server invia SOLO la chiave pubblica al client (canale insicuro va bene)

# --- Lato CLIENT ---
# Il client usa la chiave pubblica del server per generare
# CONTEMPORANEAMENTE un ciphertext e uno shared secret casuale.
# A differenza di RSA, il segreto nasce durante l'encapsulation,
# non viene scelto prima e poi cifrato.
print("[Client] Ricevuta chiave pubblica del server.")
print("[Client] Eseguo encapsulation...")
ciphertext, shared_secret_client = encrypt(public_key)
print(f"[Client] Ciphertext generato ({len(ciphertext)} byte)")
print(f"[Client] Shared secret (client): {shared_secret_client.hex()[:32]}...\n")

# Il client invia SOLO il ciphertext al server (canale insicuro va bene)

# --- Lato SERVER (decapsulation) ---
print("[Server] Ricevuto ciphertext dal client.")
print("[Server] Eseguo decapsulation con la chiave segreta...")
shared_secret_server = decrypt(secret_key, ciphertext)
print(f"[Server] Shared secret (server): {shared_secret_server.hex()[:32]}...\n")

# --- Verifica finale ---
if shared_secret_client == shared_secret_server:
    print("✅ SUCCESSO: i due shared secret combaciano!")
    print("   Client e server hanno stabilito una chiave condivisa")
    print("   senza mai trasmetterla in chiaro sulla rete.")
else:
    print("❌ ERRORE: i due shared secret NON combaciano.")


# ============================================
# PARTE 2: Firma digitale con ML-DSA-65
# ============================================
print("\n=== ML-DSA-65 Digital Signature Demo ===\n")

# --- Generazione chiavi firmatario ---
print("[Firmatario] Genero coppia di chiavi ML-DSA-65...")
sign_public_key, sign_secret_key = dsa_generate_keypair()
print(f"[Firmatario] Chiave pubblica ({len(sign_public_key)} byte)")
print(f"[Firmatario] Chiave privata ({len(sign_secret_key)} byte)\n")

# --- Messaggio da firmare ---
message = b"Comando critico: attiva modalita sicura canale MACsec"
print(f"[Firmatario] Messaggio: {message.decode()}\n")

# --- Firma ---
print("[Firmatario] Firmo il messaggio...")
signature = sign(sign_secret_key, message)
print(f"[Firmatario] Firma generata ({len(signature)} byte)\n")


def check_signature(pub_key, msg, sig):
    """Verifica una firma gestendo sia API che ritornano bool
    sia API che sollevano eccezione in caso di firma non valida."""
    try:
        result = verify(pub_key, msg, sig)
        if result is False:
            return False
        return True
    except Exception:
        return False


# --- Verifica (lato destinatario) ---
print("[Destinatario] Ricevuto messaggio + firma + chiave pubblica.")
print("[Destinatario] Verifico l'autenticita...")

if check_signature(sign_public_key, message, signature):
    print("✅ SUCCESSO: firma valida, messaggio autentico e integro.\n")
else:
    print("❌ ERRORE: firma non valida.\n")

# --- Test di sicurezza: messaggio alterato ---
tampered_message = b"Comando critico: DISATTIVA modalita sicura canale MACsec"
print("[Test tampering] Provo a verificare con messaggio alterato...")

if check_signature(sign_public_key, tampered_message, signature):
    print("❌ ERRORE CRITICO: firma accettata su messaggio alterato!")
else:
    print("✅ SUCCESSO: firma correttamente RIFIUTATA su messaggio alterato.")
