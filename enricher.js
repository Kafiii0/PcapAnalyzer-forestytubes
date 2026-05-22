'use strict';

const fs   = require('fs').promises;
const path = require('path');
const dns  = require('dns').promises;

const CACHE_DIR        = path.join(__dirname, 'brain', 'cache');
const ASN_CACHE_FILE   = path.join(CACHE_DIR, 'asn_cache.json');
const IOC_CACHE_FILE   = path.join(CACHE_DIR, 'ioc_feed_cache.json');
const PDNS_CACHE_FILE  = path.join(CACHE_DIR, 'pdns_cache.json');

const IOC_REFRESH_MS   = 6 * 60 * 60 * 1000;
const ASN_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const PDNS_CACHE_TTL_MS = 12 * 60 * 60 * 1000;

const TI_FEEDS = [
    {
        url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        name: 'ipsum',
        parser: (text) => text.split('\n')
            .filter(l => !l.startsWith('#') && l.trim())
            .map(l => l.split('\t')[0].trim())
            .filter(Boolean)
    },
    {
        url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        name: 'feodotracker',
        parser: (text) => text.split('\n')
            .filter(l => !l.startsWith('#') && l.trim())
            .map(l => l.trim())
            .filter(Boolean)
    },
    {
        url: 'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts',
        name: 'badd-boyz',
        parser: (text) => text.split('\n')
            .filter(l => !l.startsWith('#') && l.includes('0.0.0.0'))
            .map(l => l.replace('0.0.0.0 ', '').trim())
            .filter(Boolean)
    }
];

const TRUSTED_ASN_KEYWORDS = [
    'APPLE', 'MICROSOFT', 'GOOGLE', 'AKAMAI', 'CLOUDFLARE',
    'AMAZON', 'FASTLY', 'META', 'FACEBOOK', 'TWITTER',
    'LINKEDIN', 'GITHUB', 'DIGICERT', 'LETSENCRYPT',
    'VERISIGN', 'COMODO', 'SECTIGO', 'NETFLIX', 'ADOBE',
    'DROPBOX', 'ZOOM', 'SLACK', 'ATLASSIAN', 'SALESFORCE'
];

const TRUSTED_SNI_PATTERNS = [
    /\.apple\.com$/i,
    /\.icloud\.com$/i,
    /cdn-apple\.com$/i,
    /\.microsoft\.com$/i,
    /\.windows\.com$/i,
    /\.office\.com$/i,
    /\.office365\.com$/i,
    /\.live\.com$/i,
    /\.skype\.com$/i,
    /\.teams\.microsoft\.com$/i,
    /\.google\.com$/i,
    /\.googleapis\.com$/i,
    /\.gstatic\.com$/i,
    /\.googleusercontent\.com$/i,
    /\.youtube\.com$/i,
    /\.cloudflare\.com$/i,
    /\.cloudflare-dns\.com$/i,
    /\.akamai\.net$/i,
    /\.akamaiedge\.net$/i,
    /\.akamaitechnologies\.com$/i,
    /\.amazonaws\.com$/i,
    /\.awsstatic\.com$/i,
    /\.fastly\.net$/i,
    /\.fastlylb\.net$/i,
    /\.github\.com$/i,
    /\.githubusercontent\.com$/i,
    /\.cdn\.mozilla\.net$/i,
    /\.digicert\.com$/i,
    /\.letsencrypt\.org$/i,
    /\.facebook\.com$/i,
    /\.fbcdn\.net$/i,
    /\.instagram\.com$/i,
    /\.whatsapp\.net$/i,
    /\.twitter\.com$/i,
    /\.twimg\.com$/i,
    /\.linkedin\.com$/i,
    /\.licdn\.com$/i
];

const MALICIOUS_URI_PATTERNS = [
    {
        pattern: /\/api\/metrics.*stage=(credential|browser|wallet|messenger|boot|init)/i,
        label: 'Stealer Telemetry Stage',
        score: 85,
        family: 'Info Stealer'
    },
    {
        pattern: /\/api\/tasks\/[A-Za-z0-9+/=]+.*\?v=[\d.]+/i,
        label: 'C2 Task Polling (Base64 ID)',
        score: 90,
        family: 'C2 Framework'
    },
    {
        pattern: /\/api\/(join|register|checkin|check-in|ping)\/?$/i,
        label: 'C2 Registration / Heartbeat',
        score: 88,
        family: 'C2 Framework'
    },
    {
        pattern: /\/api\/tasks\/ack/i,
        label: 'C2 Task Acknowledgement',
        score: 88,
        family: 'C2 Framework'
    },
    {
        pattern: /\/(gate|panel|connect|cmd|command)\.php/i,
        label: 'Classic PHP C2 Gate',
        score: 80,
        family: 'Generic RAT'
    },
    {
        pattern: /\/[a-f0-9]{16,}(\/|$)/i,
        label: 'Hex Hash URI (Implant ID)',
        score: 65,
        family: 'Unknown Implant'
    },
    {
        pattern: /\/(upload|exfil|send|submit)\/(data|file|cred|log|info)/i,
        label: 'Data Exfiltration Endpoint',
        score: 82,
        family: 'Stealer/RAT'
    },
    {
        pattern: /\/contact\/?$/i,
        label: 'PhantomStealer Contact Endpoint',
        score: 75,
        family: 'PhantomStealer'
    },
    {
        pattern: /\/[A-Za-z0-9]{20,}\.(php|asp|aspx)\?[a-z]=[A-Za-z0-9+/=]{10,}/i,
        label: 'Obfuscated Web Shell',
        score: 78,
        family: 'Web Shell / RAT'
    }
];

let _asnCache  = {};
let _iocFeed   = new Set();
let _pdnsCache = {};
let _iocLastRefresh = 0;
let _initialized = false;

async function ensureCacheDir() {
    await fs.mkdir(CACHE_DIR, { recursive: true });
}

async function loadJSON(file, fallback) {
    try {
        const raw = await fs.readFile(file, 'utf-8');
        return JSON.parse(raw);
    } catch {
        return fallback;
    }
}

async function saveJSON(file, data) {
    try {
        await fs.writeFile(file, JSON.stringify(data, null, 2));
    } catch (e) {
        console.warn(`[enricher] Gagal menyimpan cache ${file}:`, e.message);
    }
}

async function refreshIOCFeeds(force = false) {
    const now = Date.now();
    if (!force && (now - _iocLastRefresh) < IOC_REFRESH_MS) return;

    console.log('[enricher] Refreshing Threat Intelligence feeds...');
    const fresh = new Set();
    let successCount = 0;

    for (const feed of TI_FEEDS) {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 8000);
            const resp = await fetch(feed.url, { signal: controller.signal });
            clearTimeout(timer);

            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const text = await resp.text();
            const indicators = feed.parser(text);
            indicators.forEach(i => fresh.add(i));
            successCount++;
            console.log(`[enricher]   ✓ ${feed.name}: ${indicators.length} indicators`);
        } catch (e) {
            console.warn(`[enricher]   ✗ ${feed.name} gagal: ${e.message}`);
        }
    }

    if (fresh.size > 0) {
        _iocFeed = fresh;
        _iocLastRefresh = now;
        await saveJSON(IOC_CACHE_FILE, {
            ts: now,
            indicators: [...fresh]
        });
        console.log(`[enricher] TI Feed diperbarui: ${fresh.size} total indicators dari ${successCount} feed`);
    }
}

async function getASNInfo(ip) {
    const cached = _asnCache[ip];
    if (cached && (Date.now() - cached.ts) < ASN_CACHE_TTL_MS) {
        return cached;
    }

    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1)/.test(ip)) {
        return { org: 'PRIVATE', asnName: 'RFC1918', country: 'LOCAL', ts: Date.now() };
    }

    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(`https://api.bgpview.io/ip/${ip}`, { signal: controller.signal });
        clearTimeout(timer);

        if (resp.ok) {
            const data = await resp.json();
            const prefix = data.data?.prefixes?.[0];
            const result = {
                org: prefix?.asn?.description || '',
                asnName: prefix?.asn?.name || '',
                asnNumber: prefix?.asn?.asn || 0,
                country: data.data?.rir_allocation?.country_code || '',
                ts: Date.now()
            };
            _asnCache[ip] = result;
            saveJSON(ASN_CACHE_FILE, _asnCache);
            return result;
        }
    } catch {
    }

    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);
        const resp = await fetch(`http://ip-api.com/json/${ip}?fields=org,as,country,isp`, {
            signal: controller.signal
        });
        clearTimeout(timer);

        if (resp.ok) {
            const data = await resp.json();
            const result = {
                org: data.org || data.isp || '',
                asnName: data.as || '',
                country: data.country || '',
                ts: Date.now()
            };
            _asnCache[ip] = result;
            saveJSON(ASN_CACHE_FILE, _asnCache);
            return result;
        }
    } catch {
    }

    const empty = { org: '', asnName: '', country: '', ts: Date.now() };
    _asnCache[ip] = empty;
    return empty;
}

function isTrustedASN(asnInfo) {
    if (!asnInfo || !asnInfo.org) return false;
    const orgUpper = (asnInfo.org + ' ' + asnInfo.asnName).toUpperCase();
    return TRUSTED_ASN_KEYWORDS.some(kw => orgUpper.includes(kw));
}

function isTrustedSNI(sniList) {
    if (!sniList || sniList.length === 0) return false;
    return sniList.every(sni =>
        TRUSTED_SNI_PATTERNS.some(pattern => pattern.test(sni))
    );
}

function getSNITrustLevel(sniList) {
    if (!sniList || sniList.length === 0) return 'NO_SNI';
    if (isTrustedSNI(sniList)) return 'TRUSTED';
    const trustedCount = sniList.filter(sni =>
        TRUSTED_SNI_PATTERNS.some(p => p.test(sni))
    ).length;
    if (trustedCount > 0) return 'PARTIAL';
    return 'UNKNOWN';
}

function analyzeHTTPPatterns(flow) {
    const results = [];

    const uriSources = [
        flow.http_uri,
        flow.http_host,
        flow.http_request_uri,
        ...(flow.unique_dns_domains || [])
    ].filter(Boolean);

    for (const uri of uriSources) {
        for (const { pattern, label, score, family } of MALICIOUS_URI_PATTERNS) {
            if (pattern.test(uri)) {
                results.push({ label, score, family, matched_uri: uri });
                break;
            }
        }
    }

    return results;
}

function buildSessionAggregation(flows) {
    const byDst = {};
    flows.forEach((flow, idx) => {
        const dst = flow.dst_ip;
        if (!dst) return;
        if (!byDst[dst]) byDst[dst] = [];
        byDst[dst].push({ ...flow, _idx: idx });
    });

    const aggregated = {};
    for (const [dst, sessions] of Object.entries(byDst)) {
        if (sessions.length < 3) continue;

        const totalBytes   = sessions.reduce((s, f) => s + (f.total_bytes || 0), 0);
        const totalPackets = sessions.reduce((s, f) => s + (f.packet_count || 0), 0);
        const sessionCount = sessions.length;

        const intervals = sessions
            .map(f => f.avg_interval_seconds || 0)
            .filter(i => i > 0);

        let stdDevCross = 999;
        if (intervals.length > 1) {
            const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
            const variance = intervals.reduce((s, i) => s + Math.pow(i - mean, 2), 0) / intervals.length;
            stdDevCross = Math.sqrt(variance);
        }

        const avgBytesPerSession = totalBytes / sessionCount;
        const isVeryUniform = stdDevCross < 2.0 && sessionCount >= 5;
        const isSmallConsistent = avgBytesPerSession < 2000 && sessionCount >= 5;

        aggregated[dst] = {
            sessionCount,
            totalBytes,
            totalPackets,
            avgBytesPerSession,
            stdDevCross,
            isVeryUniform,
            isSmallConsistent,
            isCrossSessionBeacon: isVeryUniform && isSmallConsistent,
            ports: [...new Set(sessions.map(f => f.dst_port).filter(Boolean))]
        };
    }

    return aggregated;
}

async function resolveWithCache(ip) {
    const cached = _pdnsCache[ip];
    if (cached && (Date.now() - cached.ts) < PDNS_CACHE_TTL_MS) {
        return cached.hostnames;
    }

    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip)) {
        return [];
    }

    try {
        const hostnames = await dns.reverse(ip);
        _pdnsCache[ip] = { hostnames, ts: Date.now() };
        saveJSON(PDNS_CACHE_FILE, _pdnsCache);
        return hostnames;
    } catch {
        _pdnsCache[ip] = { hostnames: [], ts: Date.now() };
        return [];
    }
}

async function enrich(flows) {
    if (!Array.isArray(flows) || flows.length === 0) return flows;

    refreshIOCFeeds().catch(() => {});

    const sessionAgg = buildSessionAggregation(flows);

    const publicIPs = [...new Set(
        flows
            .flatMap(f => [f.src_ip, f.dst_ip])
            .filter(ip => ip && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip))
    )];

    const CONCURRENCY = 5;
    const asnMap  = {};
    const pdnsMap = {};

    for (let i = 0; i < publicIPs.length; i += CONCURRENCY) {
        const batch = publicIPs.slice(i, i + CONCURRENCY);
        await Promise.all(batch.map(async (ip) => {
            const [asnInfo, hostnames] = await Promise.all([
                getASNInfo(ip),
                resolveWithCache(ip)
            ]);
            asnMap[ip]  = asnInfo;
            pdnsMap[ip] = hostnames;
        }));
    }

    const enriched = flows.map(flow => {
        const dstIp   = flow.dst_ip || '';
        const srcIp   = flow.src_ip || '';
        const sniList = Array.isArray(flow.tls_sni_list)
            ? flow.tls_sni_list
            : (flow.tls_sni_list ? Object.keys(flow.tls_sni_list) : []);

        const dstASN = asnMap[dstIp] || {};
        const srcASN = asnMap[srcIp] || {};

        const dstHostnames = pdnsMap[dstIp] || [];
        const allDomains   = [...sniList, ...dstHostnames];

        const asnTrusted = isTrustedASN(dstASN);
        const sniTrust   = getSNITrustLevel(sniList);
        const iocHit     = _iocFeed.has(dstIp) || _iocFeed.has(srcIp) ||
                           allDomains.some(d => _iocFeed.has(d));

        const httpMatches = analyzeHTTPPatterns(flow);

        const sessionData = sessionAgg[dstIp] || null;

        const enrichmentHints = {
            auto_trusted: asnTrusted || sniTrust === 'TRUSTED',
            ioc_feed_hit: iocHit,
            ioc_feed_indicator: iocHit ? dstIp : null,
            asn_org: dstASN.org || '',
            asn_name: dstASN.asnName || '',
            asn_country: dstASN.country || '',
            asn_trusted: asnTrusted,
            sni_trust_level: sniTrust,
            resolved_hostnames: dstHostnames,
            http_malicious_patterns: httpMatches,
            http_score_boost: httpMatches.reduce((s, m) => s + m.score, 0),
            http_family_hint: httpMatches[0]?.family || null,
            cross_session_beacon: sessionData?.isCrossSessionBeacon || false,
            cross_session_count: sessionData?.sessionCount || 1,
            cross_session_std_dev: sessionData?.stdDevCross || 999
        };

        return {
            ...flow,
            resolved_domain: dstHostnames[0] || sniList[0] || flow.resolved_domain || dstIp,
            tls_sni_list: sniList,
            enrichment: enrichmentHints
        };
    });

    return enriched;
}

function isAutoTrusted(flow) {
    if (!flow.enrichment) return false;
    return flow.enrichment.auto_trusted === true;
}

function isAutoMalicious(flow) {
    if (!flow.enrichment) return false;
    return flow.enrichment.ioc_feed_hit === true;
}

function getHTTPScoreBoost(flow) {
    if (!flow.enrichment) return 0;
    return flow.enrichment.http_score_boost || 0;
}

function getCrossSessionBeaconScore(flow) {
    if (!flow.enrichment) return 0;
    if (!flow.enrichment.cross_session_beacon) return 0;
    const sessions = flow.enrichment.cross_session_count || 1;
    return Math.min(70, 30 + (sessions * 4));
}

async function initialize() {
    if (_initialized) return;

    await ensureCacheDir();

    const savedASN = await loadJSON(ASN_CACHE_FILE, {});
    const savedPDNS = await loadJSON(PDNS_CACHE_FILE, {});
    const savedIOC = await loadJSON(IOC_CACHE_FILE, { ts: 0, indicators: [] });

    _asnCache  = savedASN;
    _pdnsCache = savedPDNS;

    if (savedIOC.indicators && savedIOC.indicators.length > 0) {
        _iocFeed = new Set(savedIOC.indicators);
        _iocLastRefresh = savedIOC.ts || 0;
        console.log(`[enricher] Loaded ${_iocFeed.size} IOC indicators dari cache`);
    }

    refreshIOCFeeds(false).catch(() => {});

    setInterval(() => {
        refreshIOCFeeds(true).catch(() => {});
    }, IOC_REFRESH_MS);

    _initialized = true;
    console.log('[enricher] ✓ Auto Intelligence Layer aktif');
}

function getStatus() {
    return {
        initialized: _initialized,
        ioc_feed_size: _iocFeed.size,
        ioc_last_refresh: new Date(_iocLastRefresh).toISOString(),
        asn_cache_size: Object.keys(_asnCache).length,
        pdns_cache_size: Object.keys(_pdnsCache).length,
        trusted_sni_patterns: TRUSTED_SNI_PATTERNS.length,
        malicious_uri_patterns: MALICIOUS_URI_PATTERNS.length
    };
}

module.exports = {
    initialize,
    enrich,
    isAutoTrusted,
    isAutoMalicious,
    getHTTPScoreBoost,
    getCrossSessionBeaconScore,
    isTrustedSNI,
    getSNITrustLevel,
    isTrustedASN,
    getStatus,
    _internal: { analyzeHTTPPatterns, buildSessionAggregation, refreshIOCFeeds }
};
