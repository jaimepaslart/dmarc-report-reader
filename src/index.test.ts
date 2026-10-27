import { deflateRawSync, gzipSync } from 'node:zlib'
import { describe, expect, it, vi } from 'vitest'
import {
  analyzeDmarcReports,
  BROWSER_READ_LIMITS,
  extractZipEntry,
  inflate,
  readZipEntries,
  decodeXmlBytes,
  detectKind,
  DmarcReportError,
  fileBytesToXmlTexts,
  parseDmarcReport,
  parseXml,
  readDmarcReportFile,
  readinessLevel,
  recognizeService,
  senderVerdict
} from './index.js'
import type { InflateFn } from './index.js'

/*
 * Rapports fictifs : structure, ordre des balises, en-têtes et espaces de noms calqués sur
 * le format publié par les grandes messageries (pièce jointe .zip ou .gz). Domaines en
 * example.com / example.net / example.org (RFC 2606), IP réservées à la documentation
 * (RFC 5737), identifiants et adresses inventés.
 */
const GOOGLE_REPORT = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>dmarc-reports@example.net</email>
    <extra_contact_info>https://example.net/dmarc</extra_contact_info>
    <report_id>4815162342108153421</report_id>
    <date_range>
      <begin>1760486400</begin>
      <end>1760572799</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
    <np>none</np>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.25</source_ip>
      <count>42</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>google</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>12</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>brevo1</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>sender-sib.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.66</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>mail.unknown.example.net</domain>
        <result>softfail</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`

const MICROSOFT_REPORT = `<?xml version="1.0"?>
<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <version>1.0</version>
  <report_metadata>
    <org_name>Outlook.com</org_name>
    <email>dmarc-reports@example.org</email>
    <report_id>9b2c4a17e0d84f3c9a6e5d1b2c3d4e5f</report_id>
    <date_range>
      <begin>1760400000</begin>
      <end>1760486400</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
    <fo>0</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.25</source_ip>
      <count>9</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>example.org</envelope_to>
      <envelope_from>example.com</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>google</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <scope>mfrom</scope>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.200</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
        <reason>
          <type>forwarded</type>
          <comment></comment>
        </reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>example.org</envelope_to>
      <envelope_from>relay.example.org</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>relay.example.org</domain>
        <scope>mfrom</scope>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>`

/** Format DMARC 2.0 : espace de noms par défaut, pas de pct, balises discovery_method/testing */
const DMARC2_REPORT = `<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <version>1.0</version>
  <report_metadata>
    <org_name>Example Mail</org_name>
    <email>dmarc@example.net</email>
    <report_id>abc-123</report_id>
    <date_range><begin>1760486400</begin><end>1760572800</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>reject</p>
    <discovery_method>treewalk</discovery_method>
    <testing>n</testing>
  </policy_published>
  <record>
    <row><source_ip>192.0.2.30</source_ip><count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>`

const encoder = new TextEncoder()

/** Construit une archive ZIP minimale (comme celles de Google), CRC non vérifié par le lecteur */
function buildZip(files: { name: string, content: Uint8Array, store?: boolean }[]): Uint8Array {
  const locals: Uint8Array[] = []
  const centrals: Uint8Array[] = []
  let offset = 0
  for (const file of files) {
    const name = encoder.encode(file.name)
    const data = file.store ? file.content : new Uint8Array(deflateRawSync(file.content))
    const method = file.store ? 0 : 8
    const local = new Uint8Array(30 + name.length + data.length)
    const lv = new DataView(local.buffer)
    lv.setUint32(0, 0x04034B50, true)
    lv.setUint16(4, 20, true)
    lv.setUint16(8, method, true)
    lv.setUint32(18, data.length, true)
    lv.setUint32(22, file.content.length, true)
    lv.setUint16(26, name.length, true)
    local.set(name, 30)
    local.set(data, 30 + name.length)
    const central = new Uint8Array(46 + name.length)
    const cv = new DataView(central.buffer)
    cv.setUint32(0, 0x02014B50, true)
    cv.setUint16(4, 20, true)
    cv.setUint16(6, 20, true)
    cv.setUint16(10, method, true)
    cv.setUint32(20, data.length, true)
    cv.setUint32(24, file.content.length, true)
    cv.setUint16(28, name.length, true)
    cv.setUint32(42, offset, true)
    central.set(name, 46)
    locals.push(local)
    centrals.push(central)
    offset += local.length
  }
  const cdSize = centrals.reduce((n, c) => n + c.length, 0)
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054B50, true)
  ev.setUint16(8, files.length, true)
  ev.setUint16(10, files.length, true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, offset, true)
  const parts = [...locals, ...centrals, eocd]
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let p = 0
  for (const part of parts) {
    out.set(part, p)
    p += part.length
  }
  return out
}

describe('parseXml', () => {
  it('lit éléments, CDATA, commentaires et entités', () => {
    const doc = parseXml('<?xml version="1.0"?><!-- c --><a x="1>2"><b>&lt;ok&gt; &amp; &#233;&#x41;</b><c><![CDATA[<brut>]]></c><d/></a>')
    const a = doc.children[0]
    expect(a?.name).toBe('a')
    expect(a?.children.map(c => c.name)).toEqual(['b', 'c', 'd'])
    expect(a?.children[0]?.text).toBe('<ok> & éA')
    expect(a?.children[1]?.text).toBe('<brut>')
  })

  it('retire les préfixes d\'espace de noms', () => {
    const doc = parseXml('<ns:feedback xmlns:ns="urn:x"><ns:version>1</ns:version></ns:feedback>')
    expect(doc.children[0]?.name).toBe('feedback')
    expect(doc.children[0]?.children[0]?.name).toBe('version')
  })

  it('ignore le DOCTYPE et ne développe aucune entité déclarée', () => {
    const doc = parseXml('<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;">]><r>&b;</r>')
    expect(doc.children[0]?.text).toBe('&b;')
  })

  it('refuse un XML mal formé', () => {
    expect(() => parseXml('<a><b></a>')).toThrow(DmarcReportError)
    expect(() => parseXml('<a>')).toThrow(DmarcReportError)
    expect(() => parseXml('<a></a></b>')).toThrow(DmarcReportError)
  })
})

describe('parseDmarcReport', () => {
  it('lit un rapport Google', () => {
    const report = parseDmarcReport(GOOGLE_REPORT)
    expect(report.orgName).toBe('google.com')
    expect(report.reportId).toBe('4815162342108153421')
    expect(report.begin).toBe(1760486400)
    expect(report.policy).toEqual({ domain: 'example.com', adkim: 'r', aspf: 'r', p: 'none', sp: 'none', pct: 100, np: 'none' })
    expect(report.records).toHaveLength(3)
    expect(report.records[0]).toMatchObject({ sourceIp: '192.0.2.25', count: 42, dkim: 'pass', spf: 'pass', headerFrom: 'example.com' })
    expect(report.records[1]?.dkimAuth).toEqual([{ domain: 'example.com', selector: 'brevo1', result: 'pass' }])
    expect(report.records[2]?.spfAuth).toEqual([{ domain: 'mail.unknown.example.net', scope: 'mfrom', result: 'softfail' }])
  })

  it('lit un rapport Microsoft (espaces de noms, envelope_from, raison forwarded)', () => {
    const report = parseDmarcReport(MICROSOFT_REPORT)
    expect(report.orgName).toBe('Outlook.com')
    expect(report.email).toBe('dmarc-reports@example.org')
    expect(report.records[1]).toMatchObject({ envelopeFrom: 'relay.example.org', reasons: ['forwarded'], count: 2 })
  })

  it('lit le format DMARC 2.0 sans pct', () => {
    const report = parseDmarcReport(DMARC2_REPORT)
    expect(report.policy.p).toBe('reject')
    expect(report.policy.pct).toBeNull()
    expect(report.records[0]?.count).toBe(5)
  })

  it('refuse un XML qui n\'est pas un rapport DMARC', () => {
    expect(() => parseDmarcReport('<rss><channel/></rss>')).toThrow(/feedback/)
    expect(() => parseDmarcReport('<feedback><autre/></feedback>')).toThrowError(DmarcReportError)
  })

  it('ramène les compteurs invalides à 0', () => {
    const xml = GOOGLE_REPORT.replace('<count>42</count>', '<count>-5</count>')
    expect(parseDmarcReport(xml).records[0]?.count).toBe(0)
  })
})

describe('décompression locale', () => {
  it('détecte le format par les octets', () => {
    expect(detectKind(new Uint8Array([0x1F, 0x8B, 8]))).toBe('gzip')
    expect(detectKind(new Uint8Array([0x50, 0x4B, 3, 4]))).toBe('zip')
    expect(detectKind(encoder.encode('<?xml'))).toBe('xml')
  })

  it('ouvre un .xml.gz (Microsoft)', async () => {
    const reports = await readDmarcReportFile(new Uint8Array(gzipSync(encoder.encode(MICROSOFT_REPORT))))
    expect(reports).toHaveLength(1)
    expect(reports[0]?.orgName).toBe('Outlook.com')
  })

  it('ouvre un .zip compressé (Google)', async () => {
    const zip = buildZip([{ name: 'google.com!example.com!1760486400!1760572799.xml', content: encoder.encode(GOOGLE_REPORT) }])
    const reports = await readDmarcReportFile(zip)
    expect(reports[0]?.records).toHaveLength(3)
  })

  it('ouvre un .zip stocké sans compression et ignore les fichiers non XML', async () => {
    const zip = buildZip([
      { name: 'lisez-moi.txt', content: encoder.encode('rien'), store: true },
      { name: 'rapport.xml', content: encoder.encode(DMARC2_REPORT), store: true }
    ])
    const texts = await fileBytesToXmlTexts(zip)
    expect(texts).toHaveLength(1)
    expect(texts[0]).toContain('dmarc-2.0')
  })

  it('refuse un fichier vide, un gzip abîmé et un zip chiffré', async () => {
    await expect(fileBytesToXmlTexts(new Uint8Array())).rejects.toMatchObject({ code: 'empty' })
    await expect(fileBytesToXmlTexts(new Uint8Array([0x1F, 0x8B, 8, 0, 1, 2, 3]))).rejects.toMatchObject({ code: 'decompression' })
    const zip = buildZip([{ name: 'r.xml', content: encoder.encode(GOOGLE_REPORT) }])
    const view = new DataView(zip.buffer)
    view.setUint16(6, 1, true) // drapeau « chiffré » dans l'en-tête local
    await expect(fileBytesToXmlTexts(zip)).rejects.toMatchObject({ code: 'unsupported-zip' })
  })

  it('stoppe une archive qui dépasse le plafond une fois décompressée', async () => {
    const big = new Uint8Array(31 * 1024 * 1024).fill(0x20)
    await expect(fileBytesToXmlTexts(new Uint8Array(gzipSync(big)))).rejects.toMatchObject({ code: 'too-large' })
  })

  it('respecte l\'encodage déclaré', () => {
    const latin1 = new Uint8Array([...encoder.encode('<?xml version="1.0" encoding="ISO-8859-1"?><a>'), 0xE9, ...encoder.encode('</a>')])
    expect(decodeXmlBytes(latin1)).toContain('<a>é</a>')
  })
})

function senderKeyOf(analysis: ReturnType<typeof analyzeDmarcReports>, ip: string): string | undefined {
  return analysis.senders.find(s => s.ips.includes(ip))?.key
}

describe('analyse', () => {
  it('reconnaît les services d\'envoi courants', () => {
    expect(recognizeService('sender-sib.com')?.id).toBe('brevo')
    expect(recognizeService('example-com.20230601.gappssmtp.com')?.id).toBe('google')
    expect(recognizeService('example.onmicrosoft.com')?.id).toBe('microsoft')
    expect(recognizeService('notgoogle.com')).toBeNull()
  })

  it('regroupe les envois et calcule les taux (Google + Microsoft)', () => {
    const analysis = analyzeDmarcReports([parseDmarcReport(GOOGLE_REPORT), parseDmarcReport(MICROSOFT_REPORT)])
    expect(analysis.reportCount).toBe(2)
    expect(analysis.domains).toEqual(['example.com'])
    expect(analysis.totalMessages).toBe(68)
    expect(analysis.passMessages).toBe(63)
    expect(analysis.failMessages).toBe(5)
    expect(analysis.dkimAlignedMessages).toBe(63)
    expect(analysis.spfAlignedMessages).toBe(51)
    expect(analysis.periodStart).toBe(1760400000)
    expect(analysis.periodDays).toBe(2)
    expect(analysis.reporters).toEqual([{ name: 'google.com', messages: 57 }, { name: 'Outlook.com', messages: 11 }])

    const google = analysis.senders.find(s => s.serviceId === 'google')
    expect(google).toMatchObject({ messages: 51, dmarcPass: 51, verdict: 'ok', serviceGuessed: true, ips: ['192.0.2.25'] })
    const brevo = analysis.senders.find(s => s.serviceId === 'brevo')
    expect(brevo).toMatchObject({ messages: 12, dkimAligned: 12, spfAligned: 0, verdict: 'ok', serviceGuessed: false })
    const unknown = analysis.senders.find(s => s.key === 'spf:mail.unknown.example.net')
    expect(unknown).toMatchObject({ messages: 3, dmarcPass: 0, verdict: 'failing' })
    const forwarded = analysis.senders.find(s => s.key === 'spf:relay.example.org')
    expect(forwarded).toMatchObject({ forwarded: 2, forwardedFailures: 2, verdict: 'forwarded' })
    expect(analysis.senders[0]?.serviceId).toBe('google')
    expect(analysis.readiness).toBe('check')
  })

  it('verdict par service', () => {
    expect(senderVerdict(100, 100)).toBe('ok')
    expect(senderVerdict(100, 98)).toBe('ok')
    expect(senderVerdict(100, 90)).toBe('partial')
    expect(senderVerdict(10, 0)).toBe('failing')
  })

  it('les échecs dus à un transfert ne pénalisent pas la source', () => {
    // 95 envois directs qui passent + 5 transferts en échec : la source reste bien configurée
    expect(senderVerdict(100, 95, 5)).toBe('ok')
    // Uniquement des transferts en échec : rien à corriger chez l'expéditeur
    expect(senderVerdict(4, 0, 4)).toBe('forwarded')
    // Transferts en échec, mais aussi des envois directs en échec
    expect(senderVerdict(10, 0, 4)).toBe('failing')
  })

  it('un groupe Google avec des transferts en échec reste prêt pour la suite', () => {
    const report = parseDmarcReport(GOOGLE_REPORT)
    const base = report.records[0]
    if (!base) throw new Error('rapport de test vide')
    const forwardedFail = { ...base, count: 3, dkim: 'fail', spf: 'fail', reasons: ['forwarded'] }
    const analysis = analyzeDmarcReports([{ ...report, records: [base, forwardedFail] }])
    const group = analysis.senders.find(s => s.key === senderKeyOf(analysis, base.sourceIp))
    expect(group?.verdict).toBe('ok')
    expect(analysis.readiness).toBe('ready')
  })

  it('aucun envoi ne passe DMARC : jamais « presque prêt »', () => {
    const report = parseDmarcReport(GOOGLE_REPORT)
    const base = report.records[0]
    if (!base) throw new Error('rapport de test vide')
    const failing = { ...base, count: 20, dkim: 'fail', spf: 'fail', reasons: [] }
    const analysis = analyzeDmarcReports([{ ...report, records: [failing] }])
    expect(analysis.passMessages).toBe(0)
    expect(analysis.senders).toHaveLength(1)
    expect(analysis.senders[0]?.verdict).toBe('failing')
    expect(analysis.readiness).toBe('none-pass')
  })

  it('niveau de préparation à p=reject', () => {
    const ok = { verdict: 'ok' } as Parameters<typeof readinessLevel>[2][number]
    const partial = { verdict: 'partial' } as Parameters<typeof readinessLevel>[2][number]
    const failing = { verdict: 'failing' } as Parameters<typeof readinessLevel>[2][number]
    const forwarded = { verdict: 'forwarded' } as Parameters<typeof readinessLevel>[2][number]
    const none = parseDmarcReport(GOOGLE_REPORT).policy
    expect(readinessLevel(0, none, [])).toBe('empty')
    expect(readinessLevel(10, none, [ok])).toBe('ready')
    expect(readinessLevel(10, none, [ok, failing])).toBe('check')
    expect(readinessLevel(10, none, [ok, partial, failing])).toBe('not-ready')
    expect(readinessLevel(10, none, [failing])).toBe('none-pass')
    expect(readinessLevel(10, none, [failing, forwarded])).toBe('none-pass')
    expect(readinessLevel(10, none, [ok, forwarded])).toBe('ready')
    expect(readinessLevel(10, { ...none, p: 'reject', pct: 100 }, [partial])).toBe('already-reject')
    expect(readinessLevel(10, { ...none, p: 'reject', pct: null }, [ok])).toBe('already-reject')
    expect(readinessLevel(10, { ...none, p: 'reject', pct: 50 }, [ok])).toBe('ready')
  })

  it('rapport DMARC 2.0 déjà en reject', () => {
    const analysis = analyzeDmarcReports([parseDmarcReport(DMARC2_REPORT)])
    expect(analysis.readiness).toBe('already-reject')
    expect(analysis.passRate).toBe(1)
  })

  it('aucun rapport', () => {
    const analysis = analyzeDmarcReports([])
    expect(analysis.readiness).toBe('empty')
    expect(analysis.policy).toBeNull()
    expect(analysis.passRate).toBe(0)
  })
})

describe('options de lecture (bornes et décompression injectée)', () => {
  it('sans options : bornes du navigateur inchangées', async () => {
    expect(BROWSER_READ_LIMITS).toEqual({ maxInputBytes: 10 * 1024 * 1024, maxXmlBytes: 30 * 1024 * 1024, maxZipEntries: 50, maxRatio: null })
    const gz = new Uint8Array(gzipSync(encoder.encode(MICROSOFT_REPORT)))
    expect(await readDmarcReportFile(gz)).toEqual(await readDmarcReportFile(gz, {}))
  })

  it('appelle la décompression injectée avec le bon format et le bon plafond', async () => {
    const spy = vi.fn<InflateFn>((bytes, format, maxBytes) => inflate(bytes, format, maxBytes))
    const gz = new Uint8Array(gzipSync(encoder.encode(MICROSOFT_REPORT)))
    await readDmarcReportFile(gz, { inflate: spy, limits: { maxXmlBytes: 5_000_000, maxRatio: 200 } })
    expect(spy).toHaveBeenCalledWith(gz, 'gzip', Math.min(5_000_000, gz.byteLength * 200))
    spy.mockClear()
    const zip = buildZip([{ name: 'r.xml', content: encoder.encode(GOOGLE_REPORT) }])
    await readDmarcReportFile(zip, { inflate: spy, limits: { maxXmlBytes: 5_000_000, maxRatio: null } })
    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy.mock.calls[0]?.[1]).toBe('deflate-raw')
    expect(spy.mock.calls[0]?.[2]).toBe(5_000_000)
  })

  it('taux de décompression borné : 200 Ko de zéros refusés avec maxRatio 10', async () => {
    const gz = new Uint8Array(gzipSync(new Uint8Array(200 * 1024)))
    await expect(fileBytesToXmlTexts(gz, { limits: { maxRatio: 10 } })).rejects.toMatchObject({ code: 'too-large' })
  })

  it('entrée ZIP dont la taille déclarée dépasse le budget : refusée sans décompression', async () => {
    const zip = buildZip([{ name: 'r.xml', content: encoder.encode(GOOGLE_REPORT) }])
    const spy = vi.fn<InflateFn>((bytes, format, maxBytes) => inflate(bytes, format, maxBytes))
    await expect(fileBytesToXmlTexts(zip, { inflate: spy, limits: { maxXmlBytes: 100 } })).rejects.toMatchObject({ code: 'too-large' })
    expect(spy).not.toHaveBeenCalled()
    const entry = readZipEntries(zip)[0]!
    await expect(extractZipEntry(zip, entry, 10, spy)).rejects.toBeInstanceOf(DmarcReportError)
    expect(spy).not.toHaveBeenCalled()
  })

  it('nombre d\'entrées ZIP borné', async () => {
    const zip = buildZip([1, 2, 3].map(n => ({ name: `r${n}.xml`, content: encoder.encode(GOOGLE_REPORT) })))
    expect(await fileBytesToXmlTexts(zip, { limits: { maxZipEntries: 2 } })).toHaveLength(2)
    expect(await fileBytesToXmlTexts(zip)).toHaveLength(3)
  })
})
