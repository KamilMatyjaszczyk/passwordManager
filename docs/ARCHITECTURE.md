# Arkitektur

Dette dokumentet forklarer hvordan prosjektet er delt opp og hvordan data
beveger seg gjennom applikasjonen.

## Oversikt

```text
Bruker
  |
  v
pm / manager.cli
  |
  +---- config --------> config.json
  +---- attempts ------> attempts.enc
  +---- clipboard -----> systemets utklippstavle
  +---- autotype ------> skrivebordets tastaturgrensesnitt
  |
  v
manager.vault
  |
  +---- keyfile -------> USB/vault.key
  +---- crypto --------> Argon2id + AES-256-GCM
  +---- schema --------> validerte innslag
  +---- file_lock -----> prosesslås
  +---- secure_file ---> atomisk og privat filbehandling
  |
  v
vault.enc
```

CLI-laget samler brukerdata og presenterer feil. Vault-laget eier
domeneoperasjonene. Crypto-laget kjenner filformat og kryptografi, mens
secure-file-laget håndterer operativsystemets filer.

## Prosjektfiler

| Fil | Ansvar |
|---|---|
| `manager/__init__.py` | Pakkeinformasjon og prosjektversjon |
| `manager/cli.py` | Argumenter, spørsmål, utskrift og kommandoarbeidsflyt |
| `manager/vault.py` | Opprette, åpne og endre vault og innslag |
| `manager/crypto.py` | Argon2id, AES-GCM og kryptert vault-format |
| `manager/vault_schema.py` | Streng validering av dekrypterte vault-data |
| `manager/keyfile.py` | Opprette og lese 64-byte keyfile |
| `manager/keyfile_location.py` | Kontroll av flyttbar enhet på hvert OS |
| `manager/config.py` | Plattformsti og validering av `config.json` |
| `manager/attempts.py` | Kryptert feilforsøksteller og cooldown |
| `manager/clipboard.py` | Sensitive markører og tidsstyrt tømming |
| `manager/autotype.py` | Wayland-, X11-, Windows- og macOS-skriving |
| `manager/file_lock.py` | Tråd- og prosesslås rundt sensitive endringer |
| `manager/secure_file.py` | Sikre lesinger, rettigheter og atomiske writes |
| `manager/main.py` | Kompatibilitetsinngang til CLI-en |
| `pyproject.toml` | Pakking, avhengigheter, `pm` og pytest-oppsett |
| `tests/` | Enhets-, sikkerhets- og ende-til-ende-tester |

## Initialisering

```text
pm init [USB_PATH]
          |
          +-- spør etter manglende vault- og USB-sti
          +-- legg til vault.key når USB_PATH er en mappe
          +-- valider flyttbar og skrivbar plassering
          +-- generer 64 tilfeldige byte hvis keyfilen mangler
          +-- valider keyfile-plassering
          +-- les master- og panic-passord
          +-- avled separat panic-nøkkel
          +-- bygg tomt og validert vault-objekt
          +-- avled vault-nøkkel med Argon2id
          +-- krypter med AES-256-GCM
          +-- verifiser midlertidig fil ved dekryptering
          +-- erstatt vault atomisk
          +-- lagre absolutte stier i config.json
```

En eksisterende vault eller keyfile overskrives ikke under opprettelse.

## Normal Opplåsing

```text
CLI leser config
      |
validerer USB-plassering
      |
leser master-passord skjult
      |
kontrollerer attempts.enc
      |
leser nøyaktig 64 byte fra keyfile
      |
Argon2id(master + keyfile + salt)
      |
AES-GCM dekryptering og tag-kontroll
      |
vault_schema validerer innholdet
      |
kommando utføres
      |
forsøkstilstand nullstilles
```

Passordet lagres ikke i konfigurasjonen. Det eksisterer bare i
prosessminnet mens kommandoen utføres.

## Feil Master-Passord

```text
Argon2id og AES-GCM-test feiler
      |
panic-verifikator testes
      |
ikke panic
      |
attempts.enc dekrypteres
      |
teller økes og cooldown beregnes
      |
ny attempts.enc skrives atomisk
```

Etter tersklene 5, 8, 10 og 15 brukes henholdsvis 30 sekunder, 2 minutter,
10 minutter og 1 time cooldown.

## Panic-Flyt

```text
opplåsingsforsøk
      |
master-kontroll feiler
      |
separat panic-verifikator treffer
      |
ta vault-lås
      |
slett vault.enc
slett config.json
slett attempts.enc
      |
behold USB-keyfile
      |
vis samme feil som vanlig feil passord
```

Panic kan kjøres mens cooldown er aktiv og ved en korrupt forsøkstilstand.
Feilmeldingen skiller ikke et panic-treff fra en vanlig opplåsingsfeil.

## Lagring Og Oppdatering

Før en vault oppdateres:

1. Dekryptert objekt valideres.
2. Eksisterende panic-metadata bevares.
3. Nytt salt og nonce genereres.
4. Hele vaulten krypteres på nytt.
5. Midlertidig fil får private rettigheter.
6. Midlertidig fil leses, dekrypteres og sammenlignes med forventet objekt.
7. `os.replace` erstatter den gamle filen atomisk.
8. Foreldremappen synkroniseres når plattformen støtter det.

Dette reduserer risikoen for en halvskrevet vault ved strømbrudd eller
prosessfeil.

## Fillåsing

Vault- og attempts-operasjoner bruker:

- lokal reentrant trådlås
- operativsystemets eksklusive fillås
- privat `.lock`-fil
- timeout på fem sekunder

Samme tråd kan gå inn i låsen flere ganger. Andre prosesser venter eller får
en tydelig busy-feil. Låsefiler kontrolleres mot symbolske lenker og
filbytte under åpning.

## Filbeskyttelse

På POSIX forsøker private filer å bruke `0600` og mapper `0700`. På Windows
brukes en begrenset ACL for gjeldende bruker og SYSTEM.

Sensitive lesinger:

- avviser symbolske lenker og reparse points
- bruker `O_NOFOLLOW` der det finnes
- krever vanlig fil
- kontrollerer inode og enhet etter åpning
- håndhever størrelsesgrenser

USB-filsystemer støtter ikke alltid private POSIX-rettigheter. Keyfilens
plassering kontrolleres derfor fysisk, men keyfilen er fortsatt lesbar for
prosesser som har tilgang til den monterte USB-en.

## Konfigurasjon

`config.json` inneholder:

```json
{
  "version": 1,
  "vault_path": "/absolutt/sti/vault.enc",
  "keyfile_path": "/flyttbar/sti/vault.key"
}
```

Konfigurasjonen inneholder ingen passord, vault-nøkkel eller keyfile-data.
Den gjør at daglige kommandoer ikke trenger stiargumenter.

`PASSWORD_MANAGER_CONFIG_DIR` finnes for testing og isolerte miljøer.

## Vault-Datamodell

Et dekryptert vault-objekt har:

```json
{
  "schema_version": 1,
  "entries": [
    {
      "id": "32 hex-tegn",
      "title": "GitHub",
      "username": "bruker",
      "password": "hemmelig",
      "url": "https://github.com",
      "notes": ""
    }
  ]
}
```

Alle felter valideres før data brukes eller lagres. ID-er er tilfeldige UUID4
uten bindestreker. Tittel kan gjentas; en unik ID brukes da som selector.

## Clipboard-Arkitektur

Backend velges i prioritert rekkefølge:

1. Wayland med `wl-copy --sensitive`
2. CopyQ med KDEs password-manager-hint
3. vanlig Wayland
4. X11 via `xclip` eller `xsel`
5. macOS med concealed pasteboard-typer
6. vanlig macOS
7. Windows native med historikk- og cloud-markører

Etter kopiering starter en separat, frakoblet ryddeprosess. Den venter 30
sekunder, leser utklippstavlen og tømmer den bare dersom verdien fortsatt er
det samme passordet. Dermed slettes ikke innhold brukeren har kopiert senere.

## Auto-Type-Arkitektur

| Plattform | Backend |
|---|---|
| Wayland | `org.freedesktop.portal.RemoteDesktop` over D-Bus |
| X11 | `xdotool`, hemmelig tekst via standard input |
| Windows | native `SendInput` |
| macOS | native CoreGraphics-events |

Auto-type validerer kontrolltegn, bruker en synlig nedtelling og trykker
aldri Enter. Login-modus setter inn én Tab mellom brukernavn og passord.

## Teststrategi

Testpakken dekker blant annet:

- kryptografisk roundtrip og manipulering
- streng skjema- og formatvalidering
- tomme master- og panic-passord
- USB-validering på Linux, macOS og Windows
- private rettigheter, lenker og atomisk skriving
- låsing mellom tråder og prosesser
- kryptert attempts-tilstand, rollback-begrensning og cooldown
- panic ved normal tilstand, cooldown og korrupt attempts-fil
- clipboard-backends og sensitiv historikkmarkering
- auto-type-backends og sikker dataoverføring
- hele CLI-arbeidsflyten gjennom subprocess-tester
- installasjonspunktet `pm`

Kjør alt med:

```bash
pytest
```
