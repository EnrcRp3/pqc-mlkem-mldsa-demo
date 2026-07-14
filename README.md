# PQC Demo — ML-KEM-768 + ML-DSA-65

Demo pratico di crittografia post-quantistica, preparato in vista del colloquio
per il ruolo di **Cryptography Engineer** presso INTEGRASYS Group (Lussemburgo).

## Cosa fa questo script

1. **Key Exchange con ML-KEM-768** (standard NIST FIPS 203)
   - Genera una coppia di chiavi lato server
   - Il client esegue *encapsulation* usando la chiave pubblica del server
   - Il server esegue *decapsulation* e ricava lo stesso shared secret
   - Verifica che client e server abbiano stabilito lo stesso segreto
     senza mai trasmetterlo in chiaro

2. **Firma digitale con ML-DSA-65** (standard NIST FIPS 204)
   - Genera una coppia di chiavi per la firma
   - Firma un messaggio di esempio
   - Verifica la firma (caso valido)
   - **Test di tampering**: verifica che un messaggio alterato venga
     correttamente rifiutato, dimostrando integrità e autenticità

## Libreria usata

[`pqcrypto`](https://pypi.org/project/pqcrypto/) — binding Python per
**PQClean**, la reference implementation degli algoritmi NIST PQC
(la stessa citata in molti annunci per ruoli di crittografia applicata,
insieme a liboqs/OQS).

Scelta motivata dal contesto: su Windows, senza toolchain di compilazione
C già pronta (git/cmake/MSVC), `liboqs-python` richiede una build da
sorgente non banale. `pqcrypto` fornisce invece wheel precompilate,
permettendo di concentrarsi sulla logica crittografica invece che sul
setup dell'ambiente.

## Come eseguirlo

```bash
pip install pqcrypto
python mlkem_demo.py
```

## Perché questo è rilevante per il ruolo

L'annuncio INTEGRASYS richiede "practical understanding of the NIST PQC
standards (ML-KEM, ML-DSA, SLH-DSA), with hands-on exposure to at least
one reference implementation (liboqs, PQClean, OpenSSL OQS provider,
or equivalent)". Questo demo copre:

- **ML-KEM-768**: uno dei tre algoritmi KEM esplicitamente richiesti
- **ML-DSA-65**: uno degli algoritmi di firma esplicitamente richiesti
- **PQClean**: una delle reference implementation esplicitamente citate

Il flusso di key exchange è concettualmente lo stesso che si userebbe
per derivare chiavi di sessione simmetriche in un protocollo ibrido
(es. TLS, IPsec, MACsec) — l'integrazione di primitive PQC in protocolli
di canale sicuro standard è uno dei task descritti nell'offerta.

## Nota di trasparenza

Questo è un demo didattico per consolidare comprensione pratica degli
algoritmi, non un'implementazione production-ready. Non include, ad
esempio, gestione sicura della memoria, protezioni side-channel,
key lifecycle management o integrazione reale in un protocollo di rete —
aspetti che rientrerebbero nel lavoro vero e proprio del ruolo.
