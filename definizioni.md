# Definizioni
## Mail Authentication
### SPF
SPF (Sender Policy Framework) è un protocollo di autenticazione email che consente al proprietario di un dominio di specificare quali server sono autorizzati a inviare email per conto di quel dominio. Il controllo SPF aiuta a evitare che malintenzionati inviino email contraffatte (spoofing) usando un dominio legittimo.

#### Esempio
Il dominio azienda.it usa Google Workspace per le sue email. Il suo amministratore DNS pubblica questo record SPF:
```
v=spf1 include:_spf.google.com -all
```
Questa configurazione:

- autorizza solo i server di Google (_spf.google.com) a inviare email per azienda.it;

- rifiuta qualsiasi altro server che tenta di inviare email con azienda.it come mittente.

Se un server non autorizzato cerca di inviare un’email come info@azienda.it, il controllo SPF fallisce e il messaggio può essere respinto o marcato come sospetto dal destinatario.

### DMARC 
DMARC (Domain-based Message Authentication, Reporting & Conformance) è un protocollo di autenticazione e protezione delle email che consente ai proprietari di domini di specificare come i server di posta dovrebbero gestire i messaggi non autenticati (ossia che non superano i controlli SPF e/o DKIM). Aiuta a prevenire spoofing, phishing e altri abusi dell'identità del dominio, migliorando la sicurezza delle comunicazioni email. 

#### Esempio
Un'azienda chiamata esempio.com implementa DMARC nel suo DNS con la seguente policy:

```
v=DMARC1; p=reject; rua=mailto:report@esempio.com
```
Questa policy:

- rifiuta automaticamente le email che non superano SPF o DKIM;

- invia i report giornalieri sulle violazioni al responsabile IT (report@esempio.com).

Se un attaccante cerca di inviare email false da info@esempio.com, i server riceventi che rispettano DMARC le rifiuteranno, proteggendo la reputazione e gli utenti dell'azienda.