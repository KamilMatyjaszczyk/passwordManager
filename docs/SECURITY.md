# Sikkerhetsmodell

Dette dokumentet beskriver hva Local USB Password Manager forsøker å
beskytte, hvilke mekanismer som brukes, og grensene for en helt lokal løsning
med en vanlig USB-minnepinne.

Prosjektet er ikke uavhengig sikkerhetsrevidert.

## Mål

Vaulten skal ikke kunne åpnes med bare én av faktorene:

```text
Noe brukeren vet: master-passord
Noe brukeren har: tilfeldig USB-keyfile
```

En angriper skal trenge:

1. `vault.enc`
2. riktig master-passord
3. den opprinnelige keyfilen

Alle tre må være tilgjengelige samtidig.

## Kryptografisk Oppsett

### Vault

| Komponent | Verdi |
|---|---|
| KDF | Argon2id |
| Minne | 65 536 KiB, 64 MiB |
| Iterasjoner | 3 |
| Parallellitet | 4 |
| Avledet nøkkel | 256 bit |
| Kryptering | AES-256-GCM |
| Salt | 16 tilfeldige byte per kryptering |
| Nonce | 12 tilfeldige byte per kryptering |
| Keyfile | 64 tilfeldige byte |

Nøkkelmaterialet er lengdeprefikset og domeneseparert:

```text
vault-domene || master-passord || USB-keyfile
                         |
                      Argon2id
                         |
                    256-bit nøkkel
```

AES-GCM autentiserer både kryptert innhold og vaultens metadata. Endring av
KDF-parametere, cipher, panic-metadata, nonce eller ciphertext skal derfor
oppdages.

Vaulten bruker streng JSON-validering:

- dupliserte felt avvises
- ukjente og manglende felt avvises
- Base64 og lengder valideres
- maksimale fil- og ciphertextstørrelser håndheves
- dekryptert innhold valideres mot vault-skjemaet

### Panic-passord

Panic-passordet bruker:

- eget tilfeldig salt og nonce
- eget domenenavn for Argon2id
- samme USB-keyfile
- en separat AES-GCM-verifikator

Det kan derfor testes uten å åpne innholdet i vaulten. Ved treff forsøker
CLI-en å slette vault, konfigurasjon og forsøkstilstand, men beholder
keyfilen.

Master-passordet kontrolleres før panic-handling når vaulten allerede er
låst. Hvis master- og panic-passord er identiske, har master-passordet
prioritet og panic-sletting utløses ikke.

Panic-sletting bruker operativsystemets vanlige filsletting. Det er ikke
sikker overskriving og gir ingen garanti mot:

- snapshots
- eksterne kopier
- filsystemjournaler
- SSD wear levelling
- profesjonell datarekonstruksjon

### Forsøkstilstand

`attempts.enc` inneholder antall feil og tidspunkt for cooldown.

Nøkkelen avledes med HKDF-SHA-256 fra:

```text
USB-keyfile + stabil vault-identitet + eget attempts-domene
```

Tilstanden krypteres og autentiseres med AES-256-GCM. Vault-identiteten er
bundet til vaultens validerte panic-metadata og følger derfor samme vault
selv om filen flyttes eller får nytt navn.

Dette beskytter mot tilfeldig innsyn, enkel redigering, feil keyfile og
sammenblanding av ulike vaulter. En eksisterende fil som ikke kan
autentiseres blir ikke slettet eller nullstilt; CLI-en blokkerer opplåsing.

## Trusselmodell

### Beskyttet

| Scenario | Resultat |
|---|---|
| Angriperen får bare `vault.enc` | Keyfilens 512 tilfeldige bit mangler |
| Angriperen får bare USB-keyfilen | Vault og master-passord mangler |
| Vaulten redigeres | AES-GCM-autentisering feiler |
| `attempts.enc` redigeres | Autentisering feiler og CLI blokkerer |
| To CLI-prosesser skriver samtidig | Fillås hindrer tapte oppdateringer |
| Skriving avbrytes | Atomisk erstatning beskytter eksisterende vault |
| Symbolsk lenke brukes mot sensitiv fil | Filen avvises |
| Konfigurasjon eller vault har ugyldig skjema | Operasjonen avvises |

### Delvis beskyttet

| Scenario | Begrensning |
|---|---|
| USB stjeles | Keyfilen kan kopieres uten spor |
| Svakt master-passord | Argon2id forsinker, men hindrer ikke ordlisteangrep |
| Utklippstavlehistorikk | Sensitive markører er bare en forespørsel til systemet |
| Panic-sletting | Vanlig filsletting er ikke garantert irreversibel |
| Lokal cooldown | Hjelper i CLI-en, men kan omgås ved offline-angrep |

### Ikke beskyttet

Prosjektet beskytter ikke mot:

- skadevare eller keylogger på maskinen
- en angriper med kontroll over brukerens aktive økt
- lesing av hemmeligheter mens vaulten er åpen
- kompromittert Python-runtime eller installerte avhengigheter
- fysisk tvang
- maskinvareangrep på USB-en
- sletting eller skade på `vault.enc`
- tap av master-passord eller keyfile
- rollback til en eldre kopi av vault eller `attempts.enc`

## Offline-Angrep

### Uten keyfile

Keyfilen genereres med operativsystemets kryptografiske tilfeldighetskilde og
inneholder 64 byte. Brute force av 512 tilfeldige bit er ikke praktisk.

### Med keyfile

En angriper som har både `vault.enc` og keyfilen kan teste
master-passordkandidater uten å bruke CLI-en:

```text
kandidat + keyfile -> Argon2id -> forsøk AES-GCM-dekryptering
```

`attempts.enc` og cooldown kan ikke forhindre dette. Angriperen kan bruke en
kopi, slette forsøkstilstanden eller skrive sitt eget verktøy.

Argon2id gjør hvert forsøk dyrere, men passordets reelle styrke er avgjørende.
Et langt, tilfeldig master-passord eller en tilfeldig flerordsfrase anbefales.
Menneskelige mønstre, navn, årstall og varianter av vanlige ord bør unngås.

## Hvorfor Attempts Ikke Ligger I Vaulten

Programmet må registrere et feil forsøk etter at dekryptering har feilet. På
det tidspunktet har programmet ikke riktig master-passord og dermed heller
ikke vault-nøkkelen.

Hvis telleren lå inni master-kryptert innhold, kunne den ikke oppdateres ved
feil passord. Derfor brukes en separat sidefil med en egen nøkkel avledet fra
keyfilen.

Dette gir manipulasjonsdeteksjon, men ikke en ikke-tilbakestillbar teller.

## Hvorfor CLI-en Ikke Kan Håndheves Offline

Når alle nødvendige hemmeligheter er eksportbare data, kan en angriper kopiere
dem og implementere samme kryptografiske kontroll utenfor CLI-en.

Følgende kan håndheve forsøk på en måte programvarefiler ikke kan:

- smartkort med ikke-eksporterbar nøkkel og intern teller
- TPM eller Secure Enclave med plattformbinding
- en ekstern server med rate limiting

Alle tre bryter minst ett av prosjektets nåværende mål om pris, portabilitet
eller full offline-drift. En vanlig USB-keyfile er derfor valgt som fysisk
separasjon, ikke som kopibeskyttet maskinvare.

## Operativ Sikkerhet

Anbefalt bruk:

1. Oppbevar USB-en separat fra datamaskinen.
2. Koble den til bare når vaulten skal brukes.
3. Ta den ut umiddelbart etterpå.
4. Ikke bruk USB-en på ukjente eller delte maskiner.
5. Ikke la keyfilen ligge i hjemmemappen, skylagring eller e-post.
6. Bruk et sterkt og unikt master-passord.
7. Hold operativsystem, Python og avhengigheter oppdatert.
8. Foretrekk `pm type` fremfor utklippstavlen når målapplikasjonen tillater det.
9. Bruk `pm get --show-password` bare når skjerm og terminalhistorikk er trygge.

En vanlig USB kan kopieres mens den er tilkoblet. Ingen programvarekontroll
kan bekrefte at keyfilen aldri har blitt kopiert.

## Ingen Gjenoppretting

Applikasjonen har bevisst ingen:

- recovery key
- backupfunksjon
- skyreplikering
- eksport av dekryptert vault
- tilbakestilling av master-passord

Tap av én nødvendig faktor betyr permanent tap av tilgang. Prosjektet kan
heller ikke beskytte mot at brukeren eller operativsystemet lager eksterne
kopier av filene.

## Avhengigheter Og Revisjon

De sentrale kryptografiske operasjonene leveres av:

- `argon2-cffi`
- `cryptography`

Egen kode håndterer sammensetning, filformat, validering og arbeidsflyt.
Automatiske tester reduserer risikoen for regresjoner, men erstatter ikke en
uavhengig kryptografisk og plattformspesifikk sikkerhetsrevisjon.

