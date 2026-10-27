/**
 * dmarc-report-reader : lecteur de rapports DMARC agrégés (RFC 7489, annexe C, et format
 * DMARC 2.0). Lecture, décompression (.gz, .zip) et analyse, sans aucune dépendance.
 *
 * Fonctionne dans le navigateur et dans Node.js 22 ou plus récent (DecompressionStream).
 *
 * Choix de conception :
 * - Aucun appel réseau : pas de résolution DNS inverse des IP, pas de bibliothèque chargée.
 *   La décompression ZIP est écrite ici (lecture du répertoire central + DecompressionStream
 *   natif), ce qui permet un usage sous une CSP stricte, sans CDN de scripts.
 * - Analyseur XML maison, volontairement minimal : les rapports DMARC n'utilisent que des
 *   éléments simples. Les déclarations DOCTYPE sont ignorées et aucune entité déclarée
 *   n'est développée (pas d'expansion exponentielle, pas de ressource externe).
 * - Tailles plafonnées (fichier reçu et contenu décompressé) pour qu'une archive piégée
 *   ne bloque pas l'onglet ou le processus.
 * - Les services reconnus (Google, Microsoft, Brevo...) le sont uniquement d'après les
 *   domaines d'authentification présents dans le rapport : l'étiquette reste indicative.
 *
 * Code issu du lecteur en ligne de MonScoreSecurite : https://monscoresecurite.fr/outils/lecteur-rapport-dmarc
 * Licence MIT.
 */

/** Taille maximale d'un fichier déposé (les rapports réels font quelques Ko) */
export const MAX_INPUT_BYTES = 10 * 1024 * 1024

/** Taille maximale du XML après décompression, par fichier */
export const MAX_XML_BYTES = 30 * 1024 * 1024

/** Nombre maximal de rapports XML lus dans une archive ZIP */
export const MAX_ZIP_ENTRIES = 50

/** En dessous de ce taux d'échec, un service est considéré comme bien configuré */
export const SENDER_OK_RATE = 0.98

/** Période d'observation conseillée avant de passer à p=reject (en jours) */
export const RECOMMENDED_OBSERVATION_DAYS = 14

/**
 * Fonction de décompression injectable : par défaut DecompressionStream (`inflate`). Côté serveur,
 * on peut passer une fonction fondée sur node:zlib avec maxOutputLength. Elle doit lever
 * DmarcReportError('too-large') au-delà de `maxBytes`.
 */
export type InflateFn = (bytes: Uint8Array, format: 'gzip' | 'deflate-raw', maxBytes: number) => Promise<Uint8Array>

/** Bornes de lecture d'un fichier de rapport */
export interface DmarcReadLimits {
  /** Taille maximale du fichier reçu (octets) */
  maxInputBytes: number
  /** Budget total de XML décompressé par fichier (octets) */
  maxXmlBytes: number
  /** Nombre maximal de rapports XML lus dans une archive ZIP */
  maxZipEntries: number
  /** Taux de décompression maximal (taille décompressée / taille compressée) ; null : non borné */
  maxRatio: number | null
}

/** Bornes par défaut (pensées pour un usage dans le navigateur) */
export const BROWSER_READ_LIMITS: DmarcReadLimits = {
  maxInputBytes: MAX_INPUT_BYTES,
  maxXmlBytes: MAX_XML_BYTES,
  maxZipEntries: MAX_ZIP_ENTRIES,
  maxRatio: null
}

export interface DmarcReadOptions {
  inflate?: InflateFn
  limits?: Partial<DmarcReadLimits>
}

export type DmarcReportErrorCode
  = | 'too-large'
    | 'empty'
    | 'unsupported-browser'
    | 'unsupported-zip'
    | 'decompression'
    | 'invalid-xml'
    | 'not-dmarc'

const ERROR_MESSAGES: Record<DmarcReportErrorCode, string> = {
  'too-large': 'Ce fichier est trop volumineux pour être lu ici (10 Mo maximum, 30 Mo une fois décompressé).',
  'empty': 'Ce fichier est vide.',
  'unsupported-browser': 'Votre navigateur ne sait pas décompresser ce fichier. Mettez-le à jour, ou décompressez le fichier puis déposez le .xml obtenu.',
  'unsupported-zip': 'Cette archive ZIP utilise un format non pris en charge (chiffrée ou très volumineuse). Décompressez-la puis déposez le fichier .xml.',
  'decompression': 'Ce fichier compressé semble abîmé : impossible de l\'ouvrir.',
  'invalid-xml': 'Ce fichier n\'est pas un XML lisible. Vérifiez qu\'il s\'agit bien de la pièce jointe d\'un rapport DMARC.',
  'not-dmarc': 'Ce fichier ne ressemble pas à un rapport DMARC agrégé (balise « feedback » absente).'
}

export class DmarcReportError extends Error {
  readonly code: DmarcReportErrorCode
  constructor(code: DmarcReportErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'DmarcReportError'
    this.code = code
  }
}

// ---------------------------------------------------------------------------
// Détection et décompression
// ---------------------------------------------------------------------------

export type ReportFileKind = 'xml' | 'gzip' | 'zip'

/** Détecte le format d'après les premiers octets (le nom de fichier n'est pas fiable) */
export function detectKind(bytes: Uint8Array): ReportFileKind {
  if (bytes.length >= 2 && bytes[0] === 0x1F && bytes[1] === 0x8B) return 'gzip'
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) return 'zip'
  return 'xml'
}

function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

/** Décompression gzip ou deflate brut via l'API native, avec plafond de taille */
export async function inflate(bytes: Uint8Array, format: 'gzip' | 'deflate-raw', maxBytes = MAX_XML_BYTES): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') throw new DmarcReportError('unsupported-browser')
  let decompressor: DecompressionStream
  try {
    decompressor = new DecompressionStream(format)
  } catch {
    throw new DmarcReportError('unsupported-browser')
  }
  const input = new Uint8Array(bytes)
  const source = new ReadableStream<BufferSource>({
    start(controller) {
      controller.enqueue(input)
      controller.close()
    }
  })
  const reader = source.pipeThrough(decompressor).getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined)
        throw new DmarcReportError('too-large')
      }
      chunks.push(value)
    }
  } catch (error) {
    if (error instanceof DmarcReportError) throw error
    throw new DmarcReportError('decompression')
  }
  return concatChunks(chunks, total)
}

export interface ZipEntry {
  name: string
  method: number
  flags: number
  compressedSize: number
  uncompressedSize: number
  localHeaderOffset: number
}

function u16(view: DataView, offset: number): number {
  return view.getUint16(offset, true)
}

function u32(view: DataView, offset: number): number {
  return view.getUint32(offset, true)
}

/** Lit le répertoire central d'une archive ZIP (sans ZIP64) */
export function readZipEntries(bytes: Uint8Array): ZipEntry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const minEocd = 22
  if (bytes.length < minEocd) throw new DmarcReportError('decompression')
  let eocd = -1
  const stop = Math.max(0, bytes.length - minEocd - 0xFFFF)
  for (let i = bytes.length - minEocd; i >= stop; i--) {
    if (u32(view, i) === 0x06054B50) {
      eocd = i
      break
    }
  }
  if (eocd < 0) throw new DmarcReportError('decompression')
  const count = u16(view, eocd + 10)
  const cdOffset = u32(view, eocd + 16)
  if (count === 0xFFFF || cdOffset === 0xFFFFFFFF) throw new DmarcReportError('unsupported-zip')

  const decoder = new TextDecoder('utf-8')
  const entries: ZipEntry[] = []
  let p = cdOffset
  for (let n = 0; n < count; n++) {
    if (p + 46 > bytes.length || u32(view, p) !== 0x02014B50) throw new DmarcReportError('decompression')
    const flags = u16(view, p + 8)
    const method = u16(view, p + 10)
    const compressedSize = u32(view, p + 20)
    const uncompressedSize = u32(view, p + 24)
    const nameLength = u16(view, p + 28)
    const extraLength = u16(view, p + 30)
    const commentLength = u16(view, p + 32)
    const localHeaderOffset = u32(view, p + 42)
    if (p + 46 + nameLength > bytes.length) throw new DmarcReportError('decompression')
    const name = decoder.decode(bytes.subarray(p + 46, p + 46 + nameLength))
    if (compressedSize === 0xFFFFFFFF || uncompressedSize === 0xFFFFFFFF || localHeaderOffset === 0xFFFFFFFF) {
      throw new DmarcReportError('unsupported-zip')
    }
    entries.push({ name, method, flags, compressedSize, uncompressedSize, localHeaderOffset })
    p += 46 + nameLength + extraLength + commentLength
  }
  return entries
}

/**
 * Extrait le contenu brut d'une entrée ZIP (méthodes 0 « stockée » et 8 « deflate »). Une entrée
 * dont la taille déclarée dépasse `maxBytes` est refusée avant toute décompression (la taille
 * réelle reste bornée par `maxBytes` : une taille déclarée mensongère ne contourne rien).
 */
export async function extractZipEntry(bytes: Uint8Array, entry: ZipEntry, maxBytes = MAX_XML_BYTES, inflateFn: InflateFn = inflate): Promise<Uint8Array> {
  if (entry.uncompressedSize > maxBytes) throw new DmarcReportError('too-large')
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const h = entry.localHeaderOffset
  if (h + 30 > bytes.length || u32(view, h) !== 0x04034B50) throw new DmarcReportError('decompression')
  // Archive chiffrée (drapeau du répertoire central ou de l'en-tête local) : non prise en charge
  if ((entry.flags | u16(view, h + 6)) & 0x1) throw new DmarcReportError('unsupported-zip')
  const start = h + 30 + u16(view, h + 26) + u16(view, h + 28)
  const end = start + entry.compressedSize
  if (end > bytes.length) throw new DmarcReportError('decompression')
  const data = bytes.subarray(start, end)
  if (entry.method === 0) {
    if (data.byteLength > maxBytes) throw new DmarcReportError('too-large')
    return data
  }
  if (entry.method === 8) return inflateFn(data, 'deflate-raw', maxBytes)
  throw new DmarcReportError('unsupported-zip')
}

/** Décode des octets XML en texte (UTF-8 par défaut, encodage déclaré sinon) */
export function decodeXmlBytes(bytes: Uint8Array): string {
  let start = 0
  if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) start = 3
  const head = new TextDecoder('latin1').decode(bytes.subarray(start, Math.min(bytes.length, start + 200)))
  const declared = /^\s*<\?xml[^>]*encoding\s*=\s*["']([A-Za-z0-9._-]+)["']/.exec(head)?.[1]
  let decoder: TextDecoder
  try {
    decoder = new TextDecoder(declared ?? 'utf-8')
  } catch {
    decoder = new TextDecoder('utf-8')
  }
  return decoder.decode(bytes.subarray(start))
}

/** Plafond d'une décompression : reste du budget, borné par le taux maximal s'il est fixé */
function decompressionCap(remaining: number, compressedSize: number, maxRatio: number | null): number {
  return maxRatio === null ? remaining : Math.min(remaining, compressedSize * maxRatio)
}

/**
 * Transforme le fichier déposé (XML, .gz ou .zip) en textes XML.
 * Une archive ZIP peut contenir plusieurs rapports.
 * Sans `options`, bornes et décompression du navigateur (BROWSER_READ_LIMITS, DecompressionStream).
 */
export async function fileBytesToXmlTexts(bytes: Uint8Array, options?: DmarcReadOptions): Promise<string[]> {
  const limits: DmarcReadLimits = { ...BROWSER_READ_LIMITS, ...options?.limits }
  const inflateFn: InflateFn = options?.inflate ?? inflate
  if (bytes.byteLength === 0) throw new DmarcReportError('empty')
  if (bytes.byteLength > limits.maxInputBytes) throw new DmarcReportError('too-large')
  const kind = detectKind(bytes)
  if (kind === 'gzip') {
    return [decodeXmlBytes(await inflateFn(bytes, 'gzip', decompressionCap(limits.maxXmlBytes, bytes.byteLength, limits.maxRatio)))]
  }
  if (kind === 'zip') {
    const files = readZipEntries(bytes).filter(e => !e.name.endsWith('/'))
    const xmlFiles = files.filter(e => /\.xml$/i.test(e.name))
    const selected = (xmlFiles.length > 0 ? xmlFiles : files).slice(0, limits.maxZipEntries)
    if (selected.length === 0) throw new DmarcReportError('empty')
    const texts: string[] = []
    let total = 0
    for (const entry of selected) {
      const remaining = limits.maxXmlBytes - total
      const cap = entry.method === 0 ? remaining : decompressionCap(remaining, entry.compressedSize, limits.maxRatio)
      const content = await extractZipEntry(bytes, entry, cap, inflateFn)
      total += content.byteLength
      texts.push(decodeXmlBytes(content))
    }
    return texts
  }
  if (bytes.byteLength > limits.maxXmlBytes) throw new DmarcReportError('too-large')
  return [decodeXmlBytes(bytes)]
}

// ---------------------------------------------------------------------------
// Analyseur XML minimal
// ---------------------------------------------------------------------------

export interface XmlNode {
  /** Nom local (préfixe d'espace de noms retiré) */
  name: string
  children: XmlNode[]
  text: string
}

function localName(qualified: string): string {
  const colon = qualified.indexOf(':')
  return colon >= 0 ? qualified.slice(colon + 1) : qualified
}

const NAMED_ENTITIES: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: '\'' }

export function decodeXmlEntities(text: string): string {
  if (!text.includes('&')) return text
  return text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (whole, ref: string) => {
    if (ref.startsWith('#x') || ref.startsWith('#X')) {
      const code = Number.parseInt(ref.slice(2), 16)
      return Number.isFinite(code) && code >= 0 && code <= 0x10FFFF ? String.fromCodePoint(code) : whole
    }
    if (ref.startsWith('#')) {
      const code = Number.parseInt(ref.slice(1), 10)
      return Number.isFinite(code) && code >= 0 && code <= 0x10FFFF ? String.fromCodePoint(code) : whole
    }
    return NAMED_ENTITIES[ref] ?? whole
  })
}

/** Analyse un document XML simple ; lève DmarcReportError('invalid-xml') s'il est mal formé */
export function parseXml(src: string): XmlNode {
  const root: XmlNode = { name: '#document', children: [], text: '' }
  const stack: XmlNode[] = [root]
  const fail = (): never => {
    throw new DmarcReportError('invalid-xml')
  }
  const top = (): XmlNode => stack[stack.length - 1] ?? fail()
  const len = src.length
  let i = 0
  while (i < len) {
    const lt = src.indexOf('<', i)
    if (lt === -1) {
      top().text += decodeXmlEntities(src.slice(i))
      break
    }
    if (lt > i) top().text += decodeXmlEntities(src.slice(i, lt))
    if (src.startsWith('<!--', lt)) {
      const end = src.indexOf('-->', lt + 4)
      if (end === -1) fail()
      i = end + 3
      continue
    }
    if (src.startsWith('<![CDATA[', lt)) {
      const end = src.indexOf(']]>', lt + 9)
      if (end === -1) fail()
      top().text += src.slice(lt + 9, end)
      i = end + 3
      continue
    }
    if (src.startsWith('<?', lt)) {
      const end = src.indexOf('?>', lt + 2)
      if (end === -1) fail()
      i = end + 2
      continue
    }
    if (src.startsWith('<!', lt)) {
      // DOCTYPE et déclarations : ignorés, sous-ensemble interne compris (aucune entité développée)
      let j = lt + 2
      let depth = 0
      while (j < len) {
        const ch = src[j]
        if (ch === '[') depth++
        else if (ch === ']') depth--
        else if (ch === '>' && depth <= 0) break
        j++
      }
      if (j >= len) fail()
      i = j + 1
      continue
    }
    if (src[lt + 1] === '/') {
      const end = src.indexOf('>', lt + 2)
      if (end === -1) fail()
      const name = localName(src.slice(lt + 2, end).trim())
      const current = top()
      if (stack.length < 2 || current.name !== name) fail()
      stack.pop()
      i = end + 1
      continue
    }
    // Balise ouvrante : chercher le « > » final en ignorant ceux des valeurs d'attributs
    let j = lt + 1
    let quote: string | null = null
    while (j < len) {
      const ch = src[j]
      if (quote) {
        if (ch === quote) quote = null
      } else if (ch === '"' || ch === '\'') {
        quote = ch
      } else if (ch === '>') {
        break
      }
      j++
    }
    if (j >= len) fail()
    let inner = src.slice(lt + 1, j)
    const selfClosing = inner.endsWith('/')
    if (selfClosing) inner = inner.slice(0, -1)
    const rawName = /^[^\s/>]+/.exec(inner)?.[0]
    if (!rawName) fail()
    const node: XmlNode = { name: localName(rawName as string), children: [], text: '' }
    top().children.push(node)
    if (!selfClosing) stack.push(node)
    i = j + 1
  }
  if (stack.length !== 1) fail()
  return root
}

function child(node: XmlNode | undefined, name: string): XmlNode | undefined {
  return node?.children.find(c => c.name === name)
}

function childrenNamed(node: XmlNode | undefined, name: string): XmlNode[] {
  return node ? node.children.filter(c => c.name === name) : []
}

function textAt(node: XmlNode | undefined, ...path: string[]): string {
  let current = node
  for (const name of path) current = child(current, name)
  return current ? current.text.trim() : ''
}

function lower(value: string): string {
  return value.trim().toLowerCase()
}

function toInt(value: string): number {
  const n = Number.parseInt(value, 10)
  return Number.isFinite(n) && n >= 0 ? n : 0
}

// ---------------------------------------------------------------------------
// Modèle d'un rapport
// ---------------------------------------------------------------------------

export interface DmarcPolicyPublished {
  domain: string
  adkim: string
  aspf: string
  p: string
  sp: string
  /** Absent du format DMARC 2.0 : null si non publié */
  pct: number | null
  np: string
}

export interface DmarcAuthDkim {
  domain: string
  selector: string
  result: string
}

export interface DmarcAuthSpf {
  domain: string
  scope: string
  result: string
}

export interface DmarcRecord {
  sourceIp: string
  count: number
  disposition: string
  /** Résultat DKIM aligné, évalué par le destinataire (pass ou fail) */
  dkim: string
  /** Résultat SPF aligné, évalué par le destinataire (pass ou fail) */
  spf: string
  reasons: string[]
  headerFrom: string
  envelopeFrom: string
  dkimAuth: DmarcAuthDkim[]
  spfAuth: DmarcAuthSpf[]
}

export interface DmarcAggregateReport {
  orgName: string
  email: string
  reportId: string
  /** Début de la période couverte (secondes Unix, UTC), 0 si absent */
  begin: number
  end: number
  policy: DmarcPolicyPublished
  records: DmarcRecord[]
}

/** Transforme le texte XML d'un rapport agrégé en objet */
export function parseDmarcReport(xml: string): DmarcAggregateReport {
  const doc = parseXml(xml)
  const feedback = child(doc, 'feedback')
  if (!feedback) throw new DmarcReportError('not-dmarc')
  const meta = child(feedback, 'report_metadata')
  const published = child(feedback, 'policy_published')
  if (!meta && !published) throw new DmarcReportError('not-dmarc')

  const pctText = textAt(published, 'pct')
  const policy: DmarcPolicyPublished = {
    domain: lower(textAt(published, 'domain')),
    adkim: lower(textAt(published, 'adkim')) || 'r',
    aspf: lower(textAt(published, 'aspf')) || 'r',
    p: lower(textAt(published, 'p')),
    sp: lower(textAt(published, 'sp')),
    pct: pctText ? Math.min(100, toInt(pctText)) : null,
    np: lower(textAt(published, 'np'))
  }

  const records: DmarcRecord[] = childrenNamed(feedback, 'record').map((record) => {
    const row = child(record, 'row')
    const evaluated = child(row, 'policy_evaluated')
    const identifiers = child(record, 'identifiers')
    const auth = child(record, 'auth_results')
    return {
      sourceIp: textAt(row, 'source_ip'),
      count: toInt(textAt(row, 'count')),
      disposition: lower(textAt(evaluated, 'disposition')) || 'none',
      dkim: lower(textAt(evaluated, 'dkim')),
      spf: lower(textAt(evaluated, 'spf')),
      reasons: childrenNamed(evaluated, 'reason').map(r => lower(textAt(r, 'type'))).filter(Boolean),
      headerFrom: lower(textAt(identifiers, 'header_from')),
      envelopeFrom: lower(textAt(identifiers, 'envelope_from')),
      dkimAuth: childrenNamed(auth, 'dkim').map(d => ({
        domain: lower(textAt(d, 'domain')),
        selector: lower(textAt(d, 'selector')),
        result: lower(textAt(d, 'result'))
      })),
      spfAuth: childrenNamed(auth, 'spf').map(s => ({
        domain: lower(textAt(s, 'domain')),
        scope: lower(textAt(s, 'scope')) || 'mfrom',
        result: lower(textAt(s, 'result'))
      }))
    }
  })

  return {
    orgName: textAt(meta, 'org_name'),
    email: textAt(meta, 'email'),
    reportId: textAt(meta, 'report_id'),
    begin: toInt(textAt(meta, 'date_range', 'begin')),
    end: toInt(textAt(meta, 'date_range', 'end')),
    policy,
    records
  }
}

/** Lit un fichier déposé (octets bruts) et renvoie le ou les rapports qu'il contient */
export async function readDmarcReportFile(bytes: Uint8Array, options?: DmarcReadOptions): Promise<DmarcAggregateReport[]> {
  const texts = await fileBytesToXmlTexts(bytes, options)
  return texts.map(parseDmarcReport)
}

// ---------------------------------------------------------------------------
// Reconnaissance des services d'envoi courants
// ---------------------------------------------------------------------------

interface KnownService {
  id: string
  label: string
  /** Domaines d'authentification (DKIM d= ou SPF) : correspondance exacte ou sous-domaine */
  domains: string[]
}

export const KNOWN_SENDERS: KnownService[] = [
  { id: 'google', label: 'Google (Gmail, Google Workspace)', domains: ['google.com', 'googlemail.com', 'gmail.com', 'gappssmtp.com'] },
  { id: 'microsoft', label: 'Microsoft (Outlook, Microsoft 365)', domains: ['outlook.com', 'onmicrosoft.com', 'hotmail.com', 'microsoft.com'] },
  { id: 'ovh', label: 'OVHcloud', domains: ['ovh.net', 'ovh.com', 'ovhcloud.com'] },
  { id: 'ionos', label: 'IONOS', domains: ['ionos.com', 'ionos.fr', 'ionos.de', 'kundenserver.de', '1and1.com'] },
  { id: 'gandi', label: 'Gandi', domains: ['gandi.net'] },
  { id: 'infomaniak', label: 'Infomaniak', domains: ['infomaniak.ch', 'infomaniak.com'] },
  { id: 'o2switch', label: 'o2switch', domains: ['o2switch.net'] },
  { id: 'zoho', label: 'Zoho Mail', domains: ['zoho.com', 'zoho.eu', 'zohomail.com', 'zohomail.eu'] },
  { id: 'brevo', label: 'Brevo (ex-Sendinblue)', domains: ['brevo.com', 'sendinblue.com', 'sender-sib.com'] },
  { id: 'mailchimp', label: 'Mailchimp', domains: ['mcsv.net', 'mcdlv.net', 'rsgsv.net', 'mailchimpapp.net', 'mandrillapp.com'] },
  { id: 'mailjet', label: 'Mailjet', domains: ['mailjet.com'] },
  { id: 'sendgrid', label: 'SendGrid', domains: ['sendgrid.net'] },
  { id: 'ses', label: 'Amazon SES', domains: ['amazonses.com'] },
  { id: 'mailgun', label: 'Mailgun', domains: ['mailgun.org', 'mailgun.net'] },
  { id: 'hubspot', label: 'HubSpot', domains: ['hubspotemail.net', 'hubspot.com'] },
  { id: 'mailerlite', label: 'MailerLite', domains: ['mailerlite.com', 'mlsend.com'] },
  { id: 'postmark', label: 'Postmark', domains: ['postmarkapp.com', 'mtasv.net'] },
  { id: 'sparkpost', label: 'SparkPost', domains: ['sparkpostmail.com'] },
  { id: 'salesforce', label: 'Salesforce', domains: ['salesforce.com', 'exacttarget.com'] },
  { id: 'shopify', label: 'Shopify', domains: ['shopify.com', 'shopifyemail.com'] },
  { id: 'zendesk', label: 'Zendesk', domains: ['zendesk.com'] }
]

/** Sélecteurs DKIM par défaut de quelques services (indice seulement) */
const KNOWN_SELECTORS: Record<string, string> = {
  google: 'google',
  selector1: 'microsoft',
  selector2: 'microsoft',
  k1: 'mailchimp',
  k2: 'mailchimp',
  k3: 'mailchimp',
  brevo1: 'brevo',
  brevo2: 'brevo',
  mailjet: 'mailjet'
}

function serviceById(id: string): KnownService | undefined {
  return KNOWN_SENDERS.find(s => s.id === id)
}

/** Service connu correspondant à un domaine d'authentification, ou null */
export function recognizeService(domain: string): KnownService | null {
  const d = lower(domain).replace(/\.$/, '')
  if (!d) return null
  return KNOWN_SENDERS.find(s => s.domains.some(known => d === known || d.endsWith(`.${known}`))) ?? null
}

// ---------------------------------------------------------------------------
// Analyse
// ---------------------------------------------------------------------------

/**
 * - ok : au moins SENDER_OK_RATE des envois directs passent DMARC ;
 * - partial : certains envois directs passent, d'autres non ;
 * - failing : aucun envoi direct ne passe ;
 * - forwarded : tous les échecs sont des transferts signalés par la messagerie
 *   (transfert, liste de diffusion), sans envoi direct : rien à corriger chez vous.
 */
export type SenderVerdict = 'ok' | 'partial' | 'failing' | 'forwarded'

export interface SenderGroup {
  key: string
  label: string
  /** Service reconnu (null si inconnu) */
  serviceId: string | null
  /** true si le service n'est deviné que par le sélecteur DKIM */
  serviceGuessed: boolean
  /** Domaines vus dans les signatures DKIM et SPF de ces envois */
  authDomains: string[]
  ips: string[]
  messages: number
  /** Messages qui passent DMARC (DKIM ou SPF aligné) */
  dmarcPass: number
  dkimAligned: number
  spfAligned: number
  /** Messages signalés comme transférés ou passés par une liste de diffusion */
  forwarded: number
  /** Parmi eux, ceux qui échouent DMARC (exclus du verdict : l'échec vient du transfert) */
  forwardedFailures: number
  verdict: SenderVerdict
}

export type ReadinessLevel = 'empty' | 'already-reject' | 'not-ready' | 'none-pass' | 'check' | 'ready'

export interface DmarcAnalysis {
  reportCount: number
  domains: string[]
  reporters: { name: string, messages: number }[]
  /** Politique publiée lors du rapport le plus récent */
  policy: DmarcPolicyPublished | null
  periodStart: number
  periodEnd: number
  periodDays: number
  totalMessages: number
  passMessages: number
  failMessages: number
  /** Taux de réussite DMARC entre 0 et 1 (0 si aucun message) */
  passRate: number
  dkimAlignedMessages: number
  spfAlignedMessages: number
  quarantined: number
  rejected: number
  senders: SenderGroup[]
  readiness: ReadinessLevel
}

const FORWARD_REASONS = new Set(['forwarded', 'mailing_list', 'trusted_forwarder'])

function senderIdentity(record: DmarcRecord): { key: string, label: string, serviceId: string | null, guessed: boolean } {
  const spfDomains = record.spfAuth.map(s => s.domain).filter(Boolean)
  if (spfDomains.length === 0 && record.envelopeFrom) spfDomains.push(record.envelopeFrom)
  const dkimDomains = record.dkimAuth.map(d => d.domain).filter(Boolean)

  for (const domain of [...dkimDomains, ...spfDomains]) {
    const service = recognizeService(domain)
    if (service) return { key: `service:${service.id}`, label: service.label, serviceId: service.id, guessed: false }
  }
  for (const dkim of record.dkimAuth) {
    const id = KNOWN_SELECTORS[dkim.selector]
    const service = id ? serviceById(id) : undefined
    if (service) return { key: `service:${service.id}`, label: `${service.label} (probable)`, serviceId: service.id, guessed: true }
  }
  if (dkimDomains.length > 0) {
    const unique = [...new Set(dkimDomains)].sort()
    return { key: `dkim:${unique.join(',')}`, label: `Envois signés par ${unique.join(', ')}`, serviceId: null, guessed: false }
  }
  if (spfDomains[0]) {
    return { key: `spf:${spfDomains[0]}`, label: `Envois depuis ${spfDomains[0]}`, serviceId: null, guessed: false }
  }
  const ip = record.sourceIp || 'inconnue'
  return { key: `ip:${ip}`, label: `Serveur non identifié (${ip})`, serviceId: null, guessed: false }
}

/**
 * Verdict d'une source. Les échecs signalés comme transferts (forwarded, mailing_list,
 * trusted_forwarder) sont exclus : un email légitime transféré par un destinataire perd
 * souvent son alignement sans que votre configuration soit en cause.
 */
export function senderVerdict(messages: number, dmarcPass: number, forwardedFailures = 0): SenderVerdict {
  const direct = messages - forwardedFailures
  if (messages > 0 && direct <= 0) return 'forwarded'
  if (direct <= 0 || dmarcPass === 0) return 'failing'
  return dmarcPass / direct >= SENDER_OK_RATE ? 'ok' : 'partial'
}

/** Regroupe et résume un ou plusieurs rapports */
export function analyzeDmarcReports(reports: DmarcAggregateReport[]): DmarcAnalysis {
  const groups = new Map<string, SenderGroup & { ipSet: Set<string>, domainSet: Set<string> }>()
  const reporters = new Map<string, number>()
  const domains = new Set<string>()
  let total = 0
  let pass = 0
  let dkimAligned = 0
  let spfAligned = 0
  let quarantined = 0
  let rejected = 0
  let start = 0
  let end = 0
  let latest: DmarcAggregateReport | null = null

  for (const report of reports) {
    if (report.policy.domain) domains.add(report.policy.domain)
    if (report.begin > 0 && (start === 0 || report.begin < start)) start = report.begin
    if (report.end > end) end = report.end
    if (!latest || report.end >= latest.end) latest = report
    let reportMessages = 0
    for (const record of report.records) {
      const count = record.count
      reportMessages += count
      total += count
      const dkimOk = record.dkim === 'pass'
      const spfOk = record.spf === 'pass'
      const passes = dkimOk || spfOk
      if (passes) pass += count
      if (dkimOk) dkimAligned += count
      if (spfOk) spfAligned += count
      if (record.disposition === 'quarantine') quarantined += count
      if (record.disposition === 'reject') rejected += count

      const identity = senderIdentity(record)
      let group = groups.get(identity.key)
      if (!group) {
        group = {
          key: identity.key,
          label: identity.label,
          serviceId: identity.serviceId,
          serviceGuessed: identity.guessed,
          authDomains: [],
          ips: [],
          messages: 0,
          dmarcPass: 0,
          dkimAligned: 0,
          spfAligned: 0,
          forwarded: 0,
          forwardedFailures: 0,
          verdict: 'failing',
          ipSet: new Set(),
          domainSet: new Set()
        }
        groups.set(identity.key, group)
      }
      group.messages += count
      if (passes) group.dmarcPass += count
      if (dkimOk) group.dkimAligned += count
      if (spfOk) group.spfAligned += count
      if (record.reasons.some(r => FORWARD_REASONS.has(r))) {
        group.forwarded += count
        if (!passes) group.forwardedFailures += count
      }
      if (record.sourceIp) group.ipSet.add(record.sourceIp)
      for (const d of record.dkimAuth) if (d.domain) group.domainSet.add(d.domain)
      for (const s of record.spfAuth) if (s.domain) group.domainSet.add(s.domain)
    }
    const reporter = report.orgName || 'Messagerie non précisée'
    reporters.set(reporter, (reporters.get(reporter) ?? 0) + reportMessages)
  }

  const senders: SenderGroup[] = [...groups.values()]
    .map(({ ipSet, domainSet, ...group }) => ({
      ...group,
      ips: [...ipSet],
      authDomains: [...domainSet].sort(),
      verdict: senderVerdict(group.messages, group.dmarcPass, group.forwardedFailures)
    }))
    .sort((a, b) => b.messages - a.messages || a.label.localeCompare(b.label, 'fr'))

  const policy = latest ? latest.policy : null
  const periodDays = start > 0 && end > start ? Math.max(1, Math.round((end - start) / 86400)) : 0

  return {
    reportCount: reports.length,
    domains: [...domains].sort(),
    reporters: [...reporters.entries()]
      .map(([name, messages]) => ({ name, messages }))
      .sort((a, b) => b.messages - a.messages),
    policy,
    periodStart: start,
    periodEnd: end,
    periodDays,
    totalMessages: total,
    passMessages: pass,
    failMessages: total - pass,
    passRate: total > 0 ? pass / total : 0,
    dkimAlignedMessages: dkimAligned,
    spfAlignedMessages: spfAligned,
    quarantined,
    rejected,
    senders,
    readiness: readinessLevel(total, policy, senders)
  }
}

/**
 * Êtes-vous prêt pour p=reject ?
 * - not-ready : un service qui envoie bien en votre nom échoue encore parfois (à corriger) ;
 * - none-pass : aucune source ne passe DMARC de façon fiable (aucun verdict « ok ») : durcir
 *   la politique ferait refuser vos propres emails ;
 * - check : vos services passent, mais des sources n'ont jamais passé les contrôles
 *   (outil oublié, transfert ou usurpation : impossible de trancher depuis le rapport) ;
 * - ready : tous les envois passent DMARC sur la période.
 */
export function readinessLevel(total: number, policy: DmarcPolicyPublished | null, senders: SenderGroup[]): ReadinessLevel {
  if (total === 0) return 'empty'
  if (policy?.p === 'reject' && (policy.pct === null || policy.pct >= 100)) return 'already-reject'
  if (senders.some(s => s.verdict === 'partial')) return 'not-ready'
  if (!senders.some(s => s.verdict === 'ok')) return 'none-pass'
  if (senders.some(s => s.verdict === 'failing')) return 'check'
  return 'ready'
}
