# dmarc-report-reader

Lecteur de rapports DMARC agrégés (les rapports `rua` envoyés par Google, Microsoft et les autres messageries) en TypeScript, sans aucune dépendance.

**Démo en ligne gratuite** : [monscoresecurite.fr/outils/lecteur-rapport-dmarc](https://monscoresecurite.fr/outils/lecteur-rapport-dmarc). Le fichier y est lu dans votre navigateur, avec ce code.

## Ce que fait la librairie

- Lit un rapport DMARC agrégé au format XML (RFC 7489, annexe C), y compris le format DMARC 2.0 (espace de noms `urn:ietf:params:xml:ns:dmarc-2.0`, sans `pct`).
- Ouvre directement la pièce jointe reçue : `.xml`, `.xml.gz` ou `.zip` (le format est détecté d'après les premiers octets, pas d'après le nom). Une archive ZIP peut contenir plusieurs rapports.
- Résume les sources d'envoi : regroupement par service reconnu (Google, Microsoft, Brevo, Mailchimp, OVHcloud...) ou par domaine d'authentification, avec, pour chacune, le nombre de messages, les messages qui passent DMARC, l'alignement DKIM et l'alignement SPF.
- Donne un verdict par source (`ok`, `partial`, `failing`, `forwarded`) et un niveau de préparation au passage à `p=reject`. Les échecs signalés comme transferts (`forwarded`, `mailing_list`, `trusted_forwarder`) ne pénalisent pas la source.

### Choix de conception

- Aucun appel réseau : pas de résolution DNS inverse, pas de bibliothèque externe.
- Décompression par l'API native `DecompressionStream` (navigateur et Node.js) ; lecture ZIP écrite à la main (répertoire central, méthodes « stockée » et « deflate »). Les archives chiffrées et ZIP64 sont refusées avec une erreur explicite.
- Analyseur XML minimal : le DOCTYPE est ignoré et aucune entité déclarée n'est développée (pas d'expansion exponentielle, pas de ressource externe).
- Tailles plafonnées par défaut : 10 Mo par fichier reçu, 30 Mo de XML une fois décompressé, 50 rapports par archive. Ces bornes sont réglables.
- La reconnaissance d'un service se fonde uniquement sur les domaines présents dans le rapport : l'étiquette reste indicative.

## Installation

Le paquet n'est pas publié sur npm. Installez-le depuis GitHub :

```bash
npm install github:jaimepaslart/dmarc-report-reader
```

Ou copiez `src/index.ts` dans votre projet : c'est un fichier unique, sans dépendance.

Environnements : navigateurs récents et Node.js 22 ou plus récent.

## Exemple

```ts
import { readFile } from 'node:fs/promises'
import { readDmarcReportFile, analyzeDmarcReports } from 'dmarc-report-reader'

// Pièce jointe telle que reçue : .xml, .xml.gz ou .zip
const bytes = new Uint8Array(await readFile('google.com!example.com!1760486400!1760572799.zip'))

const reports = await readDmarcReportFile(bytes)
const analysis = analyzeDmarcReports(reports)

console.log(analysis.domains)        // ['example.com']
console.log(analysis.totalMessages)  // nombre de messages couverts
console.log(analysis.passRate)       // part des messages qui passent DMARC (0 à 1)
console.log(analysis.readiness)      // 'ready', 'check', 'not-ready', 'none-pass', 'already-reject' ou 'empty'

for (const sender of analysis.senders) {
  console.log(sender.label, sender.messages, sender.dkimAligned, sender.spfAligned, sender.verdict)
}
```

Dans le navigateur, avec un `<input type="file">` :

```ts
const file = input.files[0]
const reports = await readDmarcReportFile(new Uint8Array(await file.arrayBuffer()))
```

Pour un texte XML déjà décompressé, `parseDmarcReport(xml)` renvoie directement le rapport.

### Principales fonctions

| Fonction | Rôle |
| --- | --- |
| `readDmarcReportFile(bytes, options?)` | Octets d'un `.xml`, `.gz` ou `.zip` vers une liste de rapports |
| `parseDmarcReport(xml)` | Texte XML vers un rapport (`DmarcAggregateReport`) |
| `analyzeDmarcReports(reports)` | Résumé : sources, alignement, verdicts, préparation à `p=reject` |
| `fileBytesToXmlTexts(bytes, options?)` | Décompression seule, renvoie les textes XML |
| `recognizeService(domain)` | Service d'envoi connu pour un domaine, ou `null` |

Les erreurs sont des `DmarcReportError` avec un `code` (`too-large`, `empty`, `unsupported-browser`, `unsupported-zip`, `decompression`, `invalid-xml`, `not-dmarc`) et un message en français destiné à l'utilisateur.

### Options

```ts
await readDmarcReportFile(bytes, {
  // Bornes de lecture (toutes facultatives)
  limits: { maxInputBytes: 5_000_000, maxXmlBytes: 20_000_000, maxZipEntries: 20, maxRatio: 200 },
  // Décompression de remplacement, par exemple node:zlib avec maxOutputLength côté serveur.
  // Elle doit lever DmarcReportError('too-large') au-delà de maxBytes.
  inflate: async (bytes, format, maxBytes) => { /* ... */ }
})
```

## Développement

```bash
npm install
npm test        # Vitest
npm run build   # tsc vers dist/
```

Les rapports utilisés dans les tests sont fictifs : domaines `example.com`, `example.net`, `example.org` et IP réservées à la documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## English

`dmarc-report-reader` is a zero-dependency TypeScript parser for DMARC aggregate (`rua`) reports. It reads the raw attachment (`.xml`, `.xml.gz` or `.zip`, detected from the bytes), parses RFC 7489 and DMARC 2.0 XML, and summarises sending sources with DMARC pass counts and SPF/DKIM alignment, a per-source verdict and a `p=reject` readiness level. It runs in modern browsers and Node.js 22+, makes no network calls, ignores DOCTYPE entities and caps input and decompressed sizes. User-facing error messages are in French. Free online demo: [monscoresecurite.fr/outils/lecteur-rapport-dmarc](https://monscoresecurite.fr/outils/lecteur-rapport-dmarc).

## Licence

[MIT](LICENSE), Paul Bihr.

Édité par [MonScoreSecurite](https://monscoresecurite.fr).
