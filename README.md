# Local USB Password Manager

[![CI](https://github.com/KamilMatyjaszczyk/passwordManager/actions/workflows/ci.yml/badge.svg)](https://github.com/KamilMatyjaszczyk/passwordManager/actions/workflows/ci.yml)

En lokal passordbehandler der en kryptert vault krever både et
master-passord og en tilfeldig keyfile på en flyttbar USB-enhet.

```text
master-passord + USB-keyfile
              |
           Argon2id
              |
      AES-256-GCM-nøkkel
              |
           vault.enc
```

Prosjektet bruker ingen konto, server, sky eller gjenopprettingstjeneste.
Versjon `0.1.0` er funksjonell og testet, men har ikke vært gjennom en
uavhengig sikkerhetsrevisjon.

## Egenskaper

- Alle innslag lagres lokalt i én kryptert vault.
- Master-passord og en 64-byte tilfeldig USB-keyfile kreves sammen.
- Keyfilen må ligge på en flyttbar enhet, utenfor hjemmefilsystemet.
- Panic-passord kan slette lokal vault, konfigurasjon og forsøkstilstand.
- Feilforsøk og cooldown lagres kryptert og autentisert i `attempts.enc`.
- Vaulten skrives atomisk og valideres før en ny versjon erstatter den gamle.
- Samtidige CLI-prosesser beskyttes av fillåsing.
- Passord kan kopieres med tidsstyrt tømming eller skrives uten utklippstavlen.
- Linux, macOS og Windows har plattformtilpasset USB-kontroll.

Den fullstendige sikkerhetsmodellen og begrensningene står i
[docs/SECURITY.md](docs/SECURITY.md).

## Krav

- Python 3.11 eller nyere
- En fysisk flyttbar USB-enhet
- Linux, macOS eller Windows

Python-avhengighetene installeres automatisk:

- `argon2-cffi`
- `cryptography`
- `dbus-next` på Linux

Noen skrivebordsfunksjoner på Linux trenger systemverktøy:

| Miljø | Utklippstavle | Automatisk skriving |
|---|---|---|
| Wayland | `wl-copy` og `wl-paste`, vanligvis fra `wl-clipboard` | Desktop Portal |
| X11 | `copyq`, `xclip` eller `xsel` | `xdotool` |
| macOS | Innebygd | Innebygd, krever tilgjengelighetstillatelse |
| Windows | Innebygd | Innebygd |

Eksempel for Debian eller Ubuntu:

```bash
sudo apt install wl-clipboard xdotool
```

Installer bare verktøyet som passer skrivebordsmiljøet ditt.

## Installasjon

Opprett et virtuelt miljø fra prosjektmappen:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

På Windows PowerShell aktiveres miljøet med:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

Installasjonen oppretter kommandoen:

```bash
pm --version
```

For utvikling og tester:

```bash
python -m pip install -e ".[test]"
pytest
```

## Første Oppsett

### 1. Koble til USB-en

Finn stien der den flyttbare enheten er montert.

Vanlige eksempler:

```text
Linux:   /media/bruker/USB
macOS:   /Volumes/USB
Windows: E:\
```

Programmet avviser en keyfile som ligger i hjemmemappen, på samme filsystem
som hjemmemappen, eller på en enhet operativsystemet ikke rapporterer som
flyttbar.

### 2. Start initialiseringen

Den anbefalte førstegangsstarten er nå:

```bash
pm init
```

CLI-en spør etter vault-sti og USB-enhet:

```text
Vault path [/gjeldende/mappe/vault.enc]:
USB device or keyfile path: /run/media/bruker/USB
```

Trykk Enter for å bruke foreslått vault-sti. Når du oppgir en USB-mappe,
opprettes keyfilen automatisk som `USB_MAPPE/vault.key`.

Det er også mulig å oppgi USB-mappen direkte:

```bash
pm init /run/media/$USER/USB
```

Eller bruke fullstendige flagg:

```bash
pm init \
  --vault "$HOME/vault.enc" \
  --keyfile /run/media/$USER/USB/vault.key
```

Flaggene kan også stå før kommandoen for bakoverkompatibilitet.

### Valgfritt: opprett keyfilen separat

`generate-keyfile` er tilgjengelig når keyfilen skal opprettes før vaulten.

Linux:

```bash
pm generate-keyfile /media/$USER/USB/vault.key
```

macOS:

```bash
pm generate-keyfile /Volumes/USB/vault.key
```

Windows PowerShell:

```powershell
pm generate-keyfile E:\vault.key
```

En eksisterende fil blir aldri overskrevet. Bruk deretter `pm init` og oppgi
den fullstendige keyfile-stien når CLI-en spør.

Programmet ber om:

1. Master-passord og bekreftelse.
2. Panic-passord og bekreftelse.

Begge må være forskjellige i praktisk bruk. Programmet avslører ikke om de
er like, men master-passordet har prioritet. Et identisk panic-passord vil
derfor ikke utløse panic-sletting.

Etter `init` lagres de absolutte stiene i lokal konfigurasjon. Du trenger
normalt ikke oppgi `--vault` eller `--keyfile` igjen.

## Daglig Bruk

Koble til USB-en, bruk ønsket kommando og ta den ut igjen når du er ferdig:

```bash
pm add
pm list
pm get GitHub
pm copy GitHub
pm type GitHub
```

Et innslag kan velges med:

- eksakt tittel, uten forskjell på store og små bokstaver
- full intern ID
- en unik ID-prefiks på minst åtte tegn

Bruk `pm list` når flere innslag har samme tittel.

### Legge til og endre innslag

```bash
pm add
pm edit GitHub
pm delete GitHub
```

`pm edit` beholder eksisterende verdi når et felt står tomt.
`pm delete` sletter bare det valgte innslaget.

### Vise og kopiere

```bash
pm get GitHub
pm get GitHub --show-password
pm copy GitHub
```

`pm get` skjuler passordet som standard. `pm copy` skriver aldri passordet i
terminalen og prøver å:

1. merke innholdet som sensitivt for utklippstavlehistorikk
2. tømme utklippstavlen etter 30 sekunder dersom innholdet er uendret

Historikkbeskyttelse avhenger av at operativsystemet og
utklippstavlebehandleren respekterer markeringen. CLI-en forteller om
beskyttelsen var tilgjengelig.

### Skrive direkte i et program

```bash
pm type GitHub
pm type GitHub --username
pm type GitHub --login --delay 5
```

- Standard er bare passordet.
- `--username` skriver bare brukernavnet.
- `--login` skriver brukernavn, Tab og passord.
- Enter trykkes aldri automatisk.
- Standard forsinkelse er tre sekunder og kan settes mellom 0 og 30.

Fokuser riktig felt før nedtellingen er ferdig. På Wayland må brukeren
godkjenne Desktop Portal-forespørselen. På macOS kan terminalen trenge
tilgjengelighetstillatelse.

### Generere passord

```bash
pm generate
pm generate --length 32
```

Kommandoen skriver bare det genererte passordet. Minimumslengden er åtte og
standardlengden er 20.

## Endre Nøkler Og Stier

Bytt master-passord:

```bash
pm change-master-password
```

Vaulten krypteres på nytt. USB-keyfilen endres ikke.

Bytt panic-passord:

```bash
pm change-panic-password
```

Flytt eller monter den samme keyfilen på en ny sti:

```bash
pm relink-keyfile /media/$USER/NEW_USB/vault.key
```

`relink-keyfile` oppretter ingen ny keyfile. Den bekrefter først at den valgte
filen faktisk kan åpne vaulten.

## Panic-Passord

Når panic-passordet brukes i stedet for master-passordet, svarer CLI-en som
ved en vanlig opplåsingsfeil:

```text
[ERROR] Could not unlock vault.
```

Samtidig forsøker programmet å slette:

- `vault.enc`
- lokal `config.json`
- lokal `attempts.enc`

USB-keyfilen slettes ikke.

Dette er vanlig filsletting. Programmet lover ikke sikker overskriving av
SSD, journaling, snapshots eller eksterne kopier. Panic-funksjonen er derfor
lokal sletting, ikke en garanti mot datarekonstruksjon.

## Feilforsøk Og Cooldown

| Antall feil | Ventetid |
|---:|---:|
| 5 | 30 sekunder |
| 8 | 2 minutter |
| 10 | 10 minutter |
| 15 eller flere | 1 time |

En vellykket opplåsing nullstiller telleren. Panic-passordet virker også mens
vaulten er midlertidig låst.

`attempts.enc` er kryptert og autentisert. Endringer, feil keyfile og
sammenblanding med en annen vault blir oppdaget og blokkerer opplåsing.
Sletting eller tilbakerulling av filen kan likevel omgå lokal cooldown ved et
offline-angrep. Se [docs/SECURITY.md](docs/SECURITY.md).

## Datafiler

Vault og keyfile plasseres av brukeren. Resten lagres i operativsystemets
konfigurasjonsmappe:

| Plattform | Standardmappe |
|---|---|
| Linux | `~/.config/password-manager/` |
| macOS | `~/Library/Application Support/PasswordManager/` |
| Windows | `%APPDATA%\PasswordManager\` |

Mappen inneholder:

| Fil | Innhold |
|---|---|
| `config.json` | Absolutte stier til vault og keyfile, ingen passord |
| `attempts.enc` | Kryptert feilforsøksteller og cooldown |
| `.attempts.enc.lock` | Låsefil for samtidige prosesser |

Ved testing kan konfigurasjonsmappen overstyres:

```bash
PASSWORD_MANAGER_CONFIG_DIR=/tmp/pm-test pm list
```

## Ingen Gjenoppretting

Programmet lager ikke backup, recovery key eller skylagring.

Du mister tilgangen permanent dersom du mister:

- master-passordet
- USB-keyfilen
- selve `vault.enc`

En ny keyfile kan ikke erstatte den opprinnelige. `relink-keyfile` endrer bare
stien til den samme filen.

## USB-Rutine

En vanlig USB-minnepinne beskytter gjennom fysisk separasjon, ikke gjennom
kopibeskyttelse. Når den er tilkoblet, kan programvare med dine
brukerrettigheter normalt kopiere keyfilen.

Anbefalt rutine:

1. Oppbevar USB-en separat fra datamaskinen.
2. Koble den til rett før bruk.
3. Bruk `pm`.
4. Ta den ut igjen med en gang.
5. Ikke bruk den til andre filer eller på ukjente maskiner.

Hvis maskinen allerede er kompromittert, kan skadevare også registrere
master-passordet eller lese hemmeligheter mens vaulten er åpen.

## Feilsøking

### Keyfilen blir avvist

Kontroller at:

- USB-en faktisk rapporteres som flyttbar av operativsystemet
- stien ikke ligger under hjemmemappen
- USB-en bruker et annet filsystem enn hjemmemappen
- filen ikke er en symbolsk lenke

### USB-en fikk en ny monteringssti

```bash
pm relink-keyfile NY_STI
```

Dette krever den opprinnelige keyfilen og riktig master-passord.

### `pm copy` finner ingen sikker backend på Linux

Wayland:

```bash
sudo apt install wl-clipboard
```

X11:

```bash
sudo apt install copyq
```

`xclip` og `xsel` støttes som alternativer, men gir bare tidsstyrt tømming
uten sensitiv historikkmarkering.

### `pm type` virker ikke

- Wayland: godkjenn Desktop Portal-dialogen.
- X11: installer `xdotool`.
- macOS: gi terminalen tilgjengelighetstillatelse.
- Kontroller at riktig målfelt har fokus.

### Se all CLI-hjelp

```bash
pm --help
pm type --help
pm COMMAND --help
```

## Videre Dokumentasjon

- [Sikkerhetsmodell og trusselmodell](docs/SECURITY.md)
- [Arkitektur og intern flyt](docs/ARCHITECTURE.md)
