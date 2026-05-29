const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const { execFile, exec, spawn } = require('child_process');
const util = require('util');
const execFileAsync = util.promisify(execFile);
const execAsync = util.promisify(exec);
const multer = require('multer');
const dns = require('dns').promises;
const tld = require('tldjs');
const ipaddr = require('ipaddr.js');
const math = require('mathjs');
const validator = require('validator');
require('dotenv').config();
const enricher = require('./enricher');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());


app.use(express.static(__dirname));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const REMOTE_BRAIN_URL = "https://overload-gap-dreaded.ngrok-free.dev/analyze";


const uploadDir = './uploads';
fs.mkdir(uploadDir, { recursive: true }).catch(err => console.error("Error creating uploads dir:", err));

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 500 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (ext !== '.pcap' && ext !== '.pcapng') {
            return cb(new Error('Hanya file .pcap dan .pcapng yang diizinkan'));
        }
        cb(null, true);
    }
});

const SYSTEM_PROMPT = `Kamu adalah Senior Threat Hunter (Kode: "The Eye") ahli dalam mendeteksi evasion malware lanjut seperti PhantomStealer. 

TUGAS UTAMA:
Lakukan analisis berbasis "Behavioral Heuristics", "Protocol Violation", dan "Statistical Anomalies" pada data koneksi jaringan JSON berikut. Gunakan KNOWLEDGE BASE / IOC CONTEXT yang dilampirkan untuk memperkuat akurasi analisis dan menyusun rekomendasi mitigasi SOC profesional.

POLA BEHAVIORAL YANG WAJIB DIIDENTIFIKASI & DIJELESKAN SECARA DETIL:
1. SMTP Outbound Anomaly (Port 587/25/465): Jelaskan "Protocol Violation" ini: Mengapa client non-email mengirimkan data outbound via SMTP ke luar negeri? Hubungkan ini dengan PhantomStealer credential exfiltration.
2. Steganography Download: Unduhan gambar berukuran sangat besar (>250KB) dari CDN/Cloudinary dengan packet count minimal (stego payload malware).
3. Chain of Infection: Pola berantai download archive (.rar) -> eksekusi script (.js) -> koneksi aktif C2 IP baru.
4. Reverse Base64 Communication & Statistical Beaconing: Keteraturan jeda transmisi sangat tinggi (StdDev Interval rendah) dan pola TCP PSH|ACK berulang secara konsisten.
5. Persistent Non-Standard Port & Keepalive: RAT maintain persistent connection using small packets over long durations.
6. FTP Credential Exfil: Outbound transfer anomaly over FTP (Port 21) indicating RedLine/AgentTesla.
7. HTTPS Exfil Suspected (LummaC2): Short duration large bytes exfil to non-CDN over HTTPS.
8. Cobalt Strike Beacon: Highly regular HTTPS beacon with very low jitter and long duration.
9. Multi-Port C2 Pattern (Emotet): Single IP connected over many ports.
10. Generic RAT / AsyncRAT / NjRAT: Known malicious ports being utilized for C2 communication.

WAJIB balas HANYA dengan format JSON murni: 
{ 
  "status_keseluruhan": "CRITICAL|SUSPICIOUS|SAFE", 
  "total_ip_dianalisis": <int>, 
  "temuan": [ 
    { 
      "ip_sumber": "", 
      "ip_tujuan": "", 
      "tingkat_ancaman": "CRITICAL|SUSPICIOUS|SAFE", 
      "alasan_teknis": "", 
      "rekomendasi_tindakan": "",
      "intel_report": { 
        "malware_family": "PhantomStealer|Lumma Stealer|Sectop RAT|Suspicious SMTP|Clean Traffic", 
        "platform_detected": "Windows|macOS/Linux",
        "ttp_mapping": "", 
        "mitre_attack": "", 
        "logic_reasoning": "Analisis forensik terperinci menjelaskan pelanggaran protokol dan pola perilaku...",
        "confidence_score": <int>,
        "severity_score": <int 1-100>,
        "behavior_flags": ["flag1", "flag2"],
        "behavior_violations": ["violation1", "violation2"],
        "tls_sni": "",
        "dns_anomaly": false
      } 
    } 
  ] 
}`;

const CODEX_DEFAULT_MODEL = process.env.CODEX_DEFAULT_MODEL || 'gpt-5.5';
const CODEX_MODEL_PATTERN = /^[A-Za-z0-9._:-]{1,80}$/;

function normalizeCodexModel(rawModel) {
    const model = String(Array.isArray(rawModel) ? rawModel[0] : (rawModel || '')).trim();
    return CODEX_MODEL_PATTERN.test(model) ? model : CODEX_DEFAULT_MODEL;
}

function extractJsonPayload(rawText) {
    let text = String(rawText || '').trim();
    if (text.includes('```json')) {
        text = text.split('```json')[1].split('```')[0];
    } else if (text.includes('```')) {
        text = text.split('```')[1].split('```')[0];
    }

    const jsonStart = text.indexOf('{');
    const jsonEnd = text.lastIndexOf('}');
    if (jsonStart !== -1 && jsonEnd !== -1 && jsonEnd > jsonStart) {
        text = text.substring(jsonStart, jsonEnd + 1);
    }
    return text;
}

function runCodexCli(prompt, model, options = {}) {
    const selectedModel = normalizeCodexModel(model);
    const timeout = options.timeout || 120000;
    const maxBuffer = options.maxBuffer || 10 * 1024 * 1024;
    const args = ['exec', '-m', selectedModel, '--skip-git-repo-check', '--ephemeral', '-'];

    return new Promise((resolve, reject) => {
        const child = spawn('codex', args, {
            cwd: __dirname,
            stdio: ['pipe', 'pipe', 'pipe'],
            env: process.env
        });

        let stdout = '';
        let stderr = '';
        let outputSize = 0;
        let settled = false;
        let timer;

        const finish = (err, result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (err) reject(err);
            else resolve(result);
        };

        const appendOutput = (target, chunk) => {
            const value = chunk.toString();
            outputSize += Buffer.byteLength(value);
            if (outputSize > maxBuffer) {
                child.kill('SIGTERM');
                finish(new Error(`Codex CLI output exceeded ${maxBuffer} bytes`));
                return target;
            }
            return target + value;
        };

        timer = setTimeout(() => {
            child.kill('SIGTERM');
            finish(new Error(`Codex CLI timeout after ${timeout}ms`));
        }, timeout);

        child.stdout.on('data', chunk => {
            stdout = appendOutput(stdout, chunk);
        });

        child.stderr.on('data', chunk => {
            stderr = appendOutput(stderr, chunk);
        });

        child.on('error', err => finish(err));
        child.on('close', code => {
            if (settled) return;
            if (code === 0) {
                finish(null, { stdout, stderr, model: selectedModel });
                return;
            }
            const details = (stderr || stdout || '').trim() || 'no output';
            finish(new Error(`Codex CLI exited with code ${code}: ${details}`));
        });

        try {
            child.stdin.end(prompt, 'utf-8');
        } catch (err) {
            child.kill('SIGTERM');
            finish(err);
        }
    });
}


async function loadIOCKnowledgeBase() {
    const kbDir = path.join(__dirname, 'brain', 'knowledge');
    try {
        await fs.mkdir(kbDir, { recursive: true });
        const files = await fs.readdir(kbDir);
        let consolidatedKB = "";
        for (const file of files) {
            if (file.endsWith('.txt') || file.endsWith('.md')) {
                const filePath = path.join(kbDir, file);
                const content = await fs.readFile(filePath, 'utf-8');
                consolidatedKB += `\n--- SOURCE: ${file} ---\n${content}\n`;
            }
        }
        return consolidatedKB || "Tidak ada berkas intelijen ancaman tambahan di knowledge base.";
    } catch (err) {
        console.warn("[WARNING] Gagal meload Knowledge Base:", err.message);
        return "Gagal memuat database IOC.";
    }
}


const IP_TO_DOMAIN_INTEL = {
    "104.21.41.172": "res.cloudinary.com",
    "185.112.144.5": "lovestoblog.com",
    "192.185.12.33": "exczx.com",
    "8.8.8.8": "dns.google",
    "1.1.1.1": "one.one.one.one"
};

async function getDomainFromIp(ip) {
    if (IP_TO_DOMAIN_INTEL[ip]) {
        return IP_TO_DOMAIN_INTEL[ip];
    }
    try {
        const hostnames = await dns.reverse(ip);
        return hostnames[0] || ip;
    } catch (err) {
        return ip;
    }
}

function checkIpType(ipStr) {
    try {
        if (!ipaddr.isValid(ipStr)) return "INVALID";
        const addr = ipaddr.parse(ipStr);
        const range = addr.range();
        if (["private", "loopback", "linkLocal", "uniqueLocal"].includes(range)) {
            return "PRIVATE";
        }
        return "PUBLIC";
    } catch (err) {
        return "INVALID";
    }
}

function sanitizeString(str) {
    if (typeof str !== 'string') return '';
    return validator.escape(str.trim());
}


function calculateStatisticalVariance(flows) {
    if (flows.length < 2) return { stdDevInterval: 999, entropyBytes: 0.1 };
    
    const intervals = flows.map(f => f.avg_interval_seconds || 0).filter(i => i > 0);
    const byteSizes = flows.map(f => f.total_bytes || 0);

    const stdDevInterval = intervals.length > 1 ? math.std(intervals) : 999;

    const totalSum = math.sum(byteSizes) || 1;
    let entropy = 0;
    byteSizes.forEach(b => {
        const p = b / totalSum;
        if (p > 0) {
            entropy -= p * Math.log2(p);
        }
    });

    return {
        stdDevInterval,
        entropyBytes: entropy
    };
}


async function parseIOCs() {
    const kbFile = path.join(__dirname, 'brain', 'knowledge', 'ioc_threat_intel.txt');
    try {
        const content = await fs.readFile(kbFile, 'utf-8');

        const ipv4Regex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
        const matchedIps = content.match(ipv4Regex) || [];
        const ipSet = new Set(matchedIps.map(ip => ip.trim()));

        const domains = [];
        const lines = content.split('\n');
        lines.forEach(line => {
            if (line.toLowerCase().includes('domains:')) {
                const parts = line.split(':')[1].split(',');
                parts.forEach(p => domains.push(p.trim()));
            }
        });
        
    
        const domainRegex = /\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}\b/g;
        const matchedDomains = content.match(domainRegex) || [];
        matchedDomains.forEach(d => domains.push(d.trim()));

        const domainSet = new Set(domains.map(d => d.toLowerCase()));

        return { ipSet, domainSet };
    } catch (err) {
        console.warn("[WARNING] Gagal memparsing IOC file:", err.message);
        return { ipSet: new Set(), domainSet: new Set() };
    }
}


function isCDNorTrustedInfra(ipStr, domain) {
    if (!ipaddr.isValid(ipStr)) return false;
    try {
        const addr = ipaddr.parse(ipStr);
        if (addr.kind() !== 'ipv4') return false;
        
        const trustedCIDRs = [
            "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13", "2.16.0.0/13",
            "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
            "142.250.0.0/15", "142.251.0.0/16", "173.194.0.0/16", "216.58.0.0/15",
            "13.64.0.0/11", "13.89.0.0/16", "20.0.0.0/8", "204.79.197.0/24", "52.0.0.0/8",
            "13.224.0.0/14", "18.160.0.0/15", "52.84.0.0/15",
            "57.144.0.0/14",  
            "52.112.0.0/14",  
            "13.107.0.0/16"   
        ];
        
        for (const cidr of trustedCIDRs) {
            if (addr.match(ipaddr.parseCIDR(cidr))) return true;
        }
        
        const trustedPrefixes = [
            "146.143.", "23.38.", "23.53.", "23.73.", "23.204.", "146.75.",
            "157.240.", "179.60.", "31.13.", "69.171.", "66.220.",
            "151.101.", "199.232.",
            "13.224.", "13.225.", "13.226.", "13.227.", "13.228.",
            "13.229.", "13.230.", "13.231.", "13.232.", "13.233.",
            "18.160.", "18.161.", "18.162.", "18.163.",
            "52.84.", "52.85.", "52.86.", "52.87.", "52.88.", "52.89.",
            "18.213.", "50.16.", "52.7.",
            "34.111.", "34.102.", "35.190.", "35.71.",
            "104.21.", "104.22.", "172.66.", "172.67.", "172.68.", "172.69."
        ];
        
        for (const prefix of trustedPrefixes) {
            if (ipStr.startsWith(prefix)) return true;
        }
        
        const d = (domain || "").toLowerCase();
        if (d.includes("cloudflare") || d.includes("akamai") || d.includes("cdn")) return true;
        
        return false;
    } catch (e) {
        return false;
    }
}

function isTrustedDomain(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
    const trustedKeywords = [
        "google", "microsoft", "teams", "skype", "cloudflare", "akamai", 
        "amazonaws", "github", "windows", "live", "office", "facebook", 
        "instagram", "twitter", "linkedin", "apple", "icloud", "yahoo", 
        "digicert", "sectigo", "letsencrypt", "verisign"
    ];
    return trustedKeywords.some(keyword => d.includes(keyword));
}

function detectNetworkContext(flows) {
    if (!flows || flows.length === 0) return "HOME";
    const privateSrcIPs = flows
        .map(f => f.src_ip)
        .filter(ip => checkIpType(ip) === "PRIVATE");
    const uniqueSrc = new Set(privateSrcIPs).size;
    
    if (uniqueSrc > 10) return "INSTITUTIONAL";
    return "HOME";
}

const RAT_STANDARD_PORTS = [80, 443, 53, 8080, 8443, 25, 587, 465, 21, 22, 23, 3389, 5900, 1433, 3306, 5432, 27017, 6379];

function getMitreMapping(flags) {
    const flagStr = Array.isArray(flags) ? flags.join(" ") : flags;
    if (flagStr.includes("Persistent Non-Standard Port") || flagStr.includes("RAT Keepalive Pattern") || flagStr.includes("NjRAT") || flagStr.includes("AsyncRAT") || flagStr.includes("DCRat")) {
        return "T1571 - Non-Standard Port | T1095 - Non-Application Layer Protocol";
    }
    if (flagStr.includes("PhantomStealer Exfil") || flagStr.includes("SMTP Outbound Anomaly") || flagStr.includes("FTP Credential Exfil") || flagStr.includes("HTTPS Exfil")) {
        return "T1048 - Exfiltration Over Alternative Protocol";
    }
    if (flagStr.includes("Automated C2 Beaconing") || flagStr.includes("Statistical Beaconing") || flagStr.includes("Suspicious Beaconing Pattern") || flagStr.includes("Cobalt Strike Beacon")) {
        return "T1071.001 - Web Protocols | T1132 - Data Encoding";
    }
    if (flagStr.includes("Stego Payload")) {
        return "T1027.003 - Steganography";
    }
    if (flagStr.includes("Multi-Port") || flagStr.includes("Inbound Data Burst")) {
        return "T1041 - Exfiltration Over C2 Channel";
    }
    return "T1071 - Application Layer Protocol";
}


const sessionLog = {};


setInterval(() => {
    const now = Date.now();
    for (const ip in sessionLog) {
        
        if (now - sessionLog[ip].timestamp > 1800000) {
            delete sessionLog[ip];
        }
    }
}, 600000);

function getGeoContext(ip) {
   
    const highRiskPrefixes = {
        "185.": "Eastern Europe/Russia (High Risk)",
        "194.": "Eastern Europe (Medium Risk)", 
        "91.": "Eastern Europe/Russia (High Risk)",
        "45.142.": "Bulletproof Hosting (Critical)",
        "193.": "Eastern Europe (Medium Risk)",
        "5.188.": "Russia/Iran (High Risk)",
        "176.": "Russia/Ukraine (Medium Risk)",
        "203.161.": "Vietnam/Asia (Medium Risk)",
        "178.": "Eastern Europe (Medium Risk)",
    };
    
    for (const [prefix, context] of Object.entries(highRiskPrefixes)) {
        if (ip.startsWith(prefix)) return context;
    }
    return null;
}

function analyzeBehavioralHeuristics(flow, index, allFlows, statsMap, iocDatabase, networkContext) {
    let score = 15; 
    const flags = [];
    const violations = [];
    
    const srcIp = sanitizeString(flow.src_ip);
    const dstIp = sanitizeString(flow.dst_ip);
    const portRaw = String(flow.dst_port || "0");
    const port = parseInt(portRaw) || 0;
    const portName = portRaw.replace(/^\d+/, '').replace(/[()]/g, '') || '';
    const ttl = flow.avg_ttl || 64;
    const packets = flow.packet_count || 0;
    const bytes = flow.total_bytes || 0;
    const interval = flow.avg_interval_seconds || 0;
    const tcpFlags = flow.tcp_flags || flow.tcp_flags_str || "NONE";
    const dnsQueryCount = flow.dns_query_count || 0;
    const hasTls = flow.has_tls_traffic || false;
    const sniList = flow.tls_sni_list ? Object.keys(flow.tls_sni_list) : [];
    
    
    const domain = flow.resolved_domain || dstIp;
    const mainDomain = tld.getDomain(domain) || domain;

    
    const srcType = checkIpType(srcIp);
    const dstType = checkIpType(dstIp);

    
    const ipStats = statsMap[srcIp] || { stdDevInterval: 999, entropyBytes: 0.1 };

    
    const isTrustedCDN = isCDNorTrustedInfra(dstIp, domain);
    if (isTrustedCDN) {
        return {
            score: 15,
            flags: ["Clean Traffic (Trusted CDN/Infra)"],
            violations: ["Traffic menuju trusted CDN/Infrastructure (Google/Microsoft/Akamai/Cloudflare)."],
            threatLevel: "SAFE",
            isAutomatedC2: false
        };
    }

    
    const isMicrosoftXMPP = port === 5222 && (
        domain.includes("microsoft") || 
        domain.includes("teams") ||
        domain.includes("skype") ||
        sniList.some(sni => sni.includes("microsoft") || sni.includes("teams") || sni.includes("skype"))
    );
    if (isMicrosoftXMPP) {
        return {
            score: 15,
            flags: ["Clean Traffic (Microsoft Teams XMPP)"],
            violations: ["Koneksi terpercaya Microsoft Teams/Skype XMPP (Port 5222)."],
            threatLevel: "SAFE",
            isAutomatedC2: false,
            confidence: 90
        };
    }

    
    const iocIps = iocDatabase?.ipSet || new Set();
    const iocDomains = iocDatabase?.domainSet || new Set();

    const isSrcIoc = iocIps.has(srcIp);
    const isDstIoc = iocIps.has(dstIp);
    const isDomainIoc = iocDomains.has(domain.toLowerCase()) || iocDomains.has(mainDomain.toLowerCase());

    if (isSrcIoc || isDstIoc || isDomainIoc) {
        const matchedIndicator = isSrcIoc ? srcIp : (isDstIoc ? dstIp : domain);
        return {
            score: 100,
            flags: ["IOC Match - Known Malicious"],
            violations: [`IOC Database Match: Koneksi aktif ke indikator ancaman terdaftar [${matchedIndicator}]. Segera isolasi host.`],
            threatLevel: "CRITICAL",
            isAutomatedC2: true
        };
    }

    
    const enr = flow.enrichment || {};

    
    if (enr.auto_trusted) {
        return {
            score: 15,
            flags: [`Clean Traffic (Auto-Trust: ${enr.asn_org || 'Known Infra'})`],
            violations: [`ASN teridentifikasi sebagai infrastruktur tepercaya: ${enr.asn_org} [${enr.asn_country}]`],
            threatLevel: 'SAFE',
            isAutomatedC2: false,
            confidence: 90
        };
    }

    
    if (enr.ioc_feed_hit) {
        return {
            score: 100,
            flags: ['TI Feed Match - Live Malicious IOC'],
            violations: [`Live Threat Intelligence Match: IP [${enr.ioc_feed_indicator}] ada di feed aktif abuse.ch/ipsum. Isolasi segera.`],
            threatLevel: 'CRITICAL',
            isAutomatedC2: true,
            confidence: 98
        };
    }

    
    if (enr.http_score_boost > 0) {
        score += enr.http_score_boost;
        enr.http_malicious_patterns.forEach(m => {
            flags.push(m.label);
            violations.push(`HTTP Pattern Match: URI mencocokkan pola [${m.label}] — Family: ${m.family}`);
        });
    }

    
    if (enr.cross_session_beacon) {
        const boost = Math.min(70, 30 + (enr.cross_session_count * 4));
        score += boost;
        flags.push('Cross-Session C2 Polling');
        violations.push(`Session Aggregation: ${enr.cross_session_count} sesi terpisah ke IP yang sama dengan interval seragam (StdDev=${enr.cross_session_std_dev.toFixed(2)}s). Pola C2 task polling.`);
    }

    
    if (enr.sni_trust_level === 'TRUSTED') {
        score = Math.max(15, score - 30);
    } else if (enr.sni_trust_level === 'PARTIAL') {
        score = Math.max(15, score - 10);
    }

    let isAutomatedC2 = false;

    
    const stdDev = ipStats.stdDevInterval || 999;
    const jitterRatio = interval > 0 ? (stdDev / interval) : 999;

    
    const ipFrequency = {};
    allFlows.forEach(f => {
        if (f.dst_ip) ipFrequency[f.dst_ip] = (ipFrequency[f.dst_ip] || 0) + 1;
    });

    
    if ((port === 587 || port === 25 || port === 465) && bytes > 3000) {
        const isSuspiciousSMTPDomain = mainDomain === "exczx.com" || (!domain.includes("gmail") && !domain.includes("outlook") && !domain.includes("yahoo") && !domain.includes("google") && !domain.includes("microsoft") && !domain.includes("mailgun") && !domain.includes("sendgrid") && !domain.includes("ses.amazonaws") && !domain.includes("smtp.office365"));
        if (isSuspiciousSMTPDomain) {
            score += 55;
            flags.push("PhantomStealer Exfil");
            violations.push(`Protocol Violation: Deteksi exfiltrasi PhantomStealer ke SMTP Port ${port} pada domain non-mail provider [${domain}].`);
        } else {
            score += 35;
            flags.push("SMTP Outbound Anomaly");
            violations.push(`Protocol Anomaly: Aliran data outbound tidak biasa ke Port SMTP ${port}.`);
        }
    }

    
    const isCloudinary = mainDomain === "cloudinary.com" || mainDomain === "res.cloudinary.com" || dstIp === "104.21.41.172";
    if (isCloudinary && bytes > 200000 && ipStats.entropyBytes > 0.8) {
        score += 40;
        flags.push("Stego Payload (Cloudinary)");
        violations.push(`Steganography Detection: Unduhan payload gambar terenkripsi berukuran besar (${(bytes/1024).toFixed(1)} KB) pada Cloudinary CDN.`);
    }

    
    if (!sessionLog[srcIp]) {
        sessionLog[srcIp] = { hasRar: false, hasJs: false, timestamp: Date.now() };
    }

    
    if (bytes > 500000 && (port === 80 || port === 443) && (mainDomain === "lovestoblog.com" || mainDomain === "cloudinary.com")) {
        sessionLog[srcIp].hasRar = true;
    }
    
    if (sessionLog[srcIp].hasRar && bytes > 2000 && bytes < 80000 && (port === 80 || port === 443)) {
        sessionLog[srcIp].hasJs = true;
    }
    
    if (sessionLog[srcIp].hasRar && sessionLog[srcIp].hasJs && port > 1024 && port !== 3000 && port !== 3001) {
        score += 60;
        flags.push("Infection Chain Active");
        violations.push(`Chain of Infection: Terdeteksi rentetan serangan terstruktur (Download RAR [lovestoblog.com] -> Eksekusi Script JS -> Koneksi C2 aktif ke Port ${port}).`);
    }

    const duration = flow.duration_seconds || 0;

    
    if (!RAT_STANDARD_PORTS.includes(port) && port < 10000 && packets > 30 && duration > 120 && dstType === "PUBLIC") {
        score += 65;
        flags.push("Persistent Non-Standard Port");
        violations.push(`RAT/Backdoor Indicator: Koneksi persisten ${duration.toFixed(1)}s ke port non-standard ${port} (${packets} paket). Pola ini konsisten dengan RAT, backdoor, atau reverse shell aktif.`);
    }

    
    const bytesPerPkt = packets > 0 ? (bytes / packets) : 0;
    if (bytesPerPkt > 0 && bytesPerPkt < 200 && packets > 40 && duration > 180 && !RAT_STANDARD_PORTS.includes(port) && dstType === "PUBLIC") {
        score += 45;
        flags.push("RAT Keepalive Pattern");
        violations.push(`Keepalive Detection: Paket sangat kecil (${bytesPerPkt.toFixed(1)} bytes/pkt) dikirim terus-menerus selama ${duration.toFixed(1)}s. Pola ini umum pada RAT yang mempertahankan koneksi aktif ke C2.`);
    }

    
    
    if (ipStats.stdDevInterval < 0.1 && interval > 0 && packets > 20) {
        if (!isTrustedCDN && port !== 80 && port !== 443 && interval > 0.5 && duration > 60) {
            score = 100;
            isAutomatedC2 = true;
            flags.push("Automated C2 Beaconing");
            violations.push(`Military-Grade Detection: Terdeteksi Automated C2 Beaconing dengan jeda waktu sangat teratur (StdDev Interval: ${ipStats.stdDevInterval.toFixed(6)}s).`);
        } else {
            score += 40;
            flags.push("Suspicious Beaconing Pattern");
            violations.push(`Statistical Anomaly: Jeda transmisi teratur namun tidak memenuhi kriteria kritis C2 (StdDev: ${ipStats.stdDevInterval.toFixed(6)}s).`);
        }
    } else if (ipStats.stdDevInterval < 0.5 && interval > 0 && packets > 20) {
        if (!isTrustedCDN && port !== 80 && port !== 443 && interval > 0.5 && duration > 60) {
            score += 40;
            flags.push("Statistical Beaconing");
            violations.push(`Statistical Anomaly: Keteraturan jeda transmisi sangat tinggi (StdDev Interval: ${ipStats.stdDevInterval.toFixed(4)}s). Terindikasi C2 Beaconing otomatis.`);
        } else {
            score += 20;
            flags.push("Suspicious Beaconing Pattern");
            violations.push(`Statistical Anomaly: Jeda transmisi teratur namun tidak memenuhi kriteria kritis C2 (StdDev: ${ipStats.stdDevInterval.toFixed(4)}s).`);
        }
    }

    
    if (port > 1024 && port < 10000 &&
        !RAT_STANDARD_PORTS.includes(port) &&
        tcpFlags.includes("PSH") && tcpFlags.includes("ACK") &&
        interval > 0.5 && interval < 10.0 &&
        packets > 30 &&
        bytesPerPkt > 50 && bytesPerPkt < 1000 &&
        dstType === "PUBLIC" && !isTrustedCDN &&
        duration > 60) {
        score += 35; 
        flags.push("Encrypted C2 Comm");
        violations.push(`Encrypted C2 Pattern: Port non-standard ${port}${portName ? ' ('+portName+')' : ''} dengan pola PSH|ACK reguler (${packets} paket, interval ${interval.toFixed(2)}s).`);
    }

    
    const NJRAT_PORTS = new Set([1177, 5552, 3782, 4782, 1234]);
    if (NJRAT_PORTS.has(port) && dstType === "PUBLIC" && !isTrustedCDN) {
        score += 75;
        flags.push("NjRAT/QuasarRAT");
        violations.push(`Known RAT Port: Port ${port} adalah signature NjRAT/QuasarRAT. Bytes/pkt=${bytesPerPkt.toFixed(0)}.`);
    }

    
    const ASYNC_PORTS = new Set([6606, 7707, 8808, 4449, 6677, 9000]);
    if (ASYNC_PORTS.has(port) && dstType === "PUBLIC" && !isTrustedCDN && packets > 15) {
        score += 70;
        flags.push("AsyncRAT/SectopRAT");
        violations.push(`AsyncRAT Signature: Port ${port} dengan ${packets} paket. C# RAT pattern terdeteksi.`);
    }

    
    if (port === 21 && dstType === "PUBLIC" && bytes > 10000) {
        score += 65;
        flags.push("FTP Credential Exfil");
        violations.push(`FTP Outbound Anomaly: Transfer ${(bytes/1024).toFixed(0)}KB via FTP ke IP publik. RedLine/AgentTesla pattern.`);
    }

    
    if (port === 443 && !isTrustedCDN && dstType === "PUBLIC" &&
        duration < 30 && bytes > 50000 && packets < 200) {
        score += 50;
        flags.push("HTTPS Exfil Suspected");
        violations.push(`Stealer Exfil Pattern: Transfer ${(bytes/1024).toFixed(0)}KB via HTTPS hanya dalam ${duration.toFixed(1)}s ke non-CDN IP. Pola LummaC2/RedLine exfiltration.`);
    }

    
    if (port === 443 && !isTrustedCDN && dstType === "PUBLIC" &&
        stdDev < 0.3 && interval > 10 && interval < 120 &&
        packets > 20 && duration > 300 &&
        bytesPerPkt < 500) {
        score += 65;
        flags.push("Cobalt Strike Beacon");
        violations.push(`Cobalt Strike Pattern: HTTPS beacon reguler (interval=${interval.toFixed(1)}s, StdDev=${stdDev.toFixed(3)}s). Jitter sangat rendah.`);
    }

    
    if (flow.multi_port_same_ip && dstType === "PUBLIC" && !isTrustedCDN) {
        score += 40;
        flags.push("Multi-Port C2 Pattern");
        violations.push(`Multi-Port Anomaly: Koneksi ke banyak port pada IP yang sama. Pola Emotet/loader module.`);
    }

    
    const DCRAT_PORTS = new Set([5000, 5001, 8888, 9999, 1337, 31337, 4444, 4445]);
    if (DCRAT_PORTS.has(port) && dstType === "PUBLIC" && !isTrustedCDN && packets > 10) {
        score += 60;
        flags.push("DCRat/Generic RAT");
        violations.push(`Hacker Port Detected: Port ${port} adalah port yang umum digunakan RAT/backdoor (DCRat, Metasploit, netcat).`);
    }

    
    if (flow.is_inbound && !isTrustedCDN && dstType === "PRIVATE" &&
        packets > 100 && bytes > 100000 && duration < 60) {
        score += 55;
        flags.push("Inbound Data Burst");
        violations.push(`C2 Response Burst: IP publik tidak dikenal mengirim ${(bytes/1024).toFixed(0)}KB dalam ${duration.toFixed(1)}s. Pola C2 mengirim payload ke victim.`);
    }

    
    if (dnsQueryCount > 30 && dstType === "PUBLIC" && !isTrustedCDN && bytesPerPkt < 250) {
        score += 65;
        flags.push("DNS Tunneling / DGA");
        violations.push(`DNS Anomaly: Volume query DNS tinggi (${dnsQueryCount} queries) dengan ukuran paket aneh. Indikasi DNS Tunneling atau C2 DGA resolusi cepat.`);
    }

    
    if (interval > 120 && interval < 86400 && stdDev < 5.0 && packets >= 3 && dstType === "PUBLIC" && !isTrustedCDN) {
        score += 70;
        flags.push("Sleep Beacon");
        violations.push(`Advanced Beaconing: Pola "Sleep" C2 terdeteksi (interval rata-rata ${interval.toFixed(0)}s, jitter/StdDev ${stdDev.toFixed(1)}s).`);
    }

    
    if (port === 443 && hasTls && sniList.length === 0 && packets > 10 && !isTrustedCDN && dstType === "PUBLIC") {
        score += 50;
        flags.push("TLS Anomaly");
        violations.push(`TLS Fingerprint Mismatch: Koneksi HTTPS aktif tanpa SNI yang valid ke IP publik tak dikenal. Pola umum custom malware crypto/JA3 evasion.`);
    }

    
    if (ipStats.entropyBytes > 0.85 && bytes > 50000 && !isTrustedCDN && dstType === "PUBLIC") {
        score += 35;
        flags.push("Obfuscated Payload");
        violations.push(`High Entropy: Varians transfer data sangat tinggi (Entropi ${ipStats.entropyBytes.toFixed(2)}). Indikasi payload terenkripsi atau steganografi.`);
    }

    
    if (
        interval > 60 &&
        jitterRatio < 0.08 &&
        packets > 10 &&
        duration > 300 &&
        dstType === "PUBLIC" && !isTrustedCDN
    ) {
        score += 55;
        flags.push("Low Jitter Beacon");
        violations.push(`Beacon jitter ratio sangat rendah (${jitterRatio.toFixed(3)} = stdDev/interval). Pola otomatis khas C2 beacon (Sliver/Havoc/CS).`);
    }

    
    if (
        (ipFrequency[dstIp] || 0) <= 2 &&
        dstType === "PUBLIC" &&
        !isTrustedCDN &&
        packets > 5
    ) {
        score += 20;
        flags.push("Rare External Endpoint");
        violations.push(`Endpoint muncul sangat jarang dalam capture (${ipFrequency[dstIp] || 1}x). Pola fresh C2 infra atau disposable VPS.`);
    }

    
    if (
        bytesPerPkt > 50 &&
        bytesPerPkt < 400 &&
        packets > 20 &&
        stdDev < 1.0 &&
        dstType === "PUBLIC" && !isTrustedCDN
    ) {
        score += 25;
        flags.push("Consistent Packet Cadence");
        violations.push(`Ukuran paket dan interval sangat konsisten (${bytesPerPkt.toFixed(0)} bytes/pkt, stdDev ${stdDev.toFixed(3)}s). Traffic manusia organik jauh lebih random.`);
    }

    
    if (
        duration > 1800 &&
        bytes < 50000 &&
        packets > 20 &&
        !isTrustedCDN &&
        dstType === "PUBLIC"
    ) {
        score += 35;
        flags.push("Low-and-Slow C2");
        violations.push(`Koneksi berlangsung ${(duration/60).toFixed(1)} menit dengan volume sangat rendah (${(bytes/1024).toFixed(1)}KB). Pola stealth RAT / dormant implant.`);
    }

    const geoContext = getGeoContext(dstIp);
    if (geoContext && dstType === "PUBLIC" && !isTrustedCDN && score > 30) {
        score += 15;
        violations.push(`GeoIP Alert: Destination ${dstIp} teridentifikasi dari region ${geoContext}.`);
    }

    
    if (srcType === "PRIVATE" && dstType === "PRIVATE") {
        score = Math.max(10, score - 30);
    }

    
    
    
    const hasValidSNI = sniList.length > 0;
    const packetVarianceHigh = stdDev > 2.0;
    const veryShortSession = duration < 5 && packets < 10;

    if (hasValidSNI) score = Math.max(15, score - 15);       
    if (packetVarianceHigh) score = Math.max(15, score - 10); 
    if (veryShortSession) score = Math.max(15, score - 10);   

    
    
    
    const txBytes = flow.tx_bytes || bytes;          
    const rxBytes = flow.rx_bytes || 1;              
    const outboundRatio = txBytes / rxBytes;

    if (
        outboundRatio > 5 &&
        ipStats.entropyBytes > 0.8 &&
        bytes > 20000 &&
        dstType === "PUBLIC" && !isTrustedCDN
    ) {
        score += 45;
        flags.push("Exfil Traffic Bias");
        violations.push(`Traffic Direction: Outbound/Inbound ratio ${outboundRatio.toFixed(1)}x dengan entropi tinggi (${ipStats.entropyBytes.toFixed(2)}). Indikasi eksfiltrasi data aktif.`);
    }

    
    
    
    const avgBurst = duration > 0 ? (bytes / duration) : 0;
    if (
        avgBurst < 20 &&
        duration > 600 &&
        packets > 15 &&
        dstType === "PUBLIC" && !isTrustedCDN
    ) {
        score += 30;
        flags.push("Beacon Lifecycle Pattern");
        violations.push(`Lifecycle: Throughput rata-rata sangat rendah (${avgBurst.toFixed(1)} B/s selama ${(duration/60).toFixed(1)} menit). Pola beacon keep-alive klasik.`);
    }

    
    
    
    
    const signalSleepBeacon   = flags.includes("Sleep Beacon");
    const signalLowJitter     = flags.includes("Low Jitter Beacon");
    const signalDnsTunnel     = flags.includes("DNS Tunneling / DGA");
    const signalRareEndpoint  = flags.includes("Rare External Endpoint");
    const signalHighEntropy   = flags.includes("Obfuscated Payload");
    const signalLowAndSlow    = flags.includes("Low-and-Slow C2");
    const signalTLSAnomaly    = flags.includes("TLS Anomaly");
    const signalCadence       = flags.includes("Consistent Packet Cadence");
    const signalExfil         = flags.includes("Exfil Traffic Bias");
    const signalBeaconLC      = flags.includes("Beacon Lifecycle Pattern");

    const correlatedSignals = [
        signalSleepBeacon, signalLowJitter, signalDnsTunnel, signalRareEndpoint,
        signalHighEntropy, signalLowAndSlow, signalTLSAnomaly, signalCadence,
        signalExfil, signalBeaconLC
    ].filter(Boolean).length;

    if (correlatedSignals >= 3) {
        const boost = correlatedSignals >= 5 ? 55 : 35;
        score += boost;
        flags.push("Correlated Multi-Signal");
        violations.push(`Multi-Signal Correlation: ${correlatedSignals} indikator independen terpicu secara bersamaan. False positive sangat tidak mungkin pada kondisi ini.`);
    }

    
    let applyConfidenceDecay = false;
    if (isTrustedDomain(domain) || (sniList.length > 0 && sniList.every(sni => isTrustedDomain(sni)))) {
        score = Math.max(15, score - 40);
        applyConfidenceDecay = true;
    }

    if (networkContext === "INSTITUTIONAL") {
        score = Math.max(15, score - 15);
    }

    const finalScore = Math.min(100, score);
    let threatLevel = "SAFE";
    if (finalScore >= 75) threatLevel = "CRITICAL";
    else if (finalScore >= 40) threatLevel = "SUSPICIOUS";

    
    
    const uniqueFlags = new Set(flags).size;
    let confidence = 40;
    confidence += uniqueFlags * 8;
    if (isAutomatedC2) confidence += 20;
    if (finalScore >= 80) confidence += 15;
    if (iocIps.has(dstIp)) confidence += 25;
    
    if (applyConfidenceDecay) {
        confidence = Math.max(20, confidence - 30);
    }
    
    confidence = Math.min(100, confidence);

    return {
        score: finalScore,
        flags: flags.length > 0 ? flags : ["Clean Traffic"],
        violations: violations.length > 0 ? violations : ["Tidak ada pelanggaran protokol."],
        threatLevel: threatLevel,
        isAutomatedC2: isAutomatedC2,
        confidence: confidence
    };
}


function localFallbackAnalysis(parsedData, statsMap, iocDatabase) {
    console.log("[*] Menjalankan Local Deterministic Heuristics Engine (Super Premium)...");
    let countCritical = 0;
    let countSuspicious = 0;
    
    const networkContext = detectNetworkContext(parsedData);
    
    const temuan = parsedData.map((flow, index) => {
        const heuristic = analyzeBehavioralHeuristics(flow, index, parsedData, statsMap, iocDatabase, networkContext);
        if (heuristic.threatLevel === "CRITICAL") countCritical++;
        else if (heuristic.threatLevel === "SUSPICIOUS") countSuspicious++;

        const platform = (flow.avg_ttl || 64) > 90 ? "Windows" : "macOS/Linux";
        
        return {
            ip_sumber: flow.src_ip,
            ip_tujuan: flow.dst_ip,
            tingkat_ancaman: heuristic.threatLevel,
            alasan_teknis: heuristic.violations.join(" | "),
            rekomendasi_tindakan: heuristic.threatLevel === "CRITICAL" ? "Segera blokir IP tujuan pada firewall dan lakukan isolasi host." : "Pantau terus aktivitas host.",
            intel_report: {
                malware_family: heuristic.flags.join(", "),
                platform_detected: platform,
                ttp_mapping: "T1071.001 - Application Layer Protocol: Web Protocols",
                mitre_attack: getMitreMapping(heuristic.flags),
                logic_reasoning: heuristic.violations.join(" | "),
                confidence_score: 100,
                severity_score: heuristic.score,
                behavior_flags: heuristic.flags,
                behavior_violations: heuristic.violations,
                tls_sni: flow.tls_sni_list && flow.tls_sni_list.length > 0 ? flow.tls_sni_list.join(", ") : "",
                dns_anomaly: flow.dns_query_count > 50 || (flow.unique_dns_domains && flow.unique_dns_domains.length > 10)
            }
        };
    });

    let status = "SAFE";
    if (countCritical > 0) status = "CRITICAL";
    else if (countSuspicious > 0) status = "SUSPICIOUS";

    return {
        status_keseluruhan: status,
        total_ip_dianalisis: parsedData.length,
        temuan: temuan,
        engine_used: "LOCAL_FAST_ENGINE"
    };
}


async function processAndAnalyze(pcapFilePath, res, req) {
    try {
        
        console.log(`[*] Executing extractor.exe on: ${pcapFilePath}`);
        try {
            const platformExt = process.platform === 'win32' ? 'extractor.exe' : './extractor';
            await execFileAsync(platformExt, [pcapFilePath]);
        } catch (execErr) {
            console.error("[ERROR] Gagal menjalankan extractor:", execErr.message);
            return res.status(500).json({ error: "Gagal memproses file PCAP menggunakan Go Extractor." });
        }

        
        let fileContent;
        try {
            fileContent = await fs.readFile('output.json', 'utf-8');
            if (!fileContent || fileContent.trim() === "") {
                throw new Error("File output.json kosong.");
            }
        } catch (err) {
            console.error("[ERROR] Gagal membaca output.json:", err.message);
            return res.status(404).json({ error: "Data PCAP belum tersedia. Pastikan program Golang sudah dieksekusi terlebih dahulu." });
        }

        
        let parsedData;
        try {
            parsedData = JSON.parse(fileContent);
        } catch (err) {
            return res.status(400).json({ error: "Format output.json tidak valid." });
        }

        if (!Array.isArray(parsedData) || parsedData.length === 0) {
            return res.status(400).json({ error: "Tidak ada data aliran (flow) untuk dianalisis dalam PCAP ini." });
        }

        let isTruncated = false;
        if (parsedData.length > 200) {
            parsedData = parsedData.slice(0, 200);
            isTruncated = true;
            console.warn("[WARNING] Data melebihi 200 flow. Memotong data untuk efisiensi.");
        }

        
        
        
        const flowsBySrcIp = {};
        parsedData.forEach(flow => {
            const src = flow.src_ip;
            if (!flowsBySrcIp[src]) flowsBySrcIp[src] = [];
            flowsBySrcIp[src].push(flow);
        });

        const statsMap = {};
        Object.keys(flowsBySrcIp).forEach(src => {
            statsMap[src] = calculateStatisticalVariance(flowsBySrcIp[src]);
        });

        
        
        
        const resolvedData = await Promise.all(parsedData.map(async (flow) => {
            const domain = await getDomainFromIp(flow.dst_ip);
            return {
                ...flow,
                resolved_domain: domain
            };
        }));

        
        const iocDatabase = await parseIOCs();

        
        const enrichedData = await enricher.enrich(resolvedData);

        
        const networkContext = detectNetworkContext(enrichedData);

        
        const parsedWithHeuristics = enrichedData.map((flow, index) => {
            const heuristic = analyzeBehavioralHeuristics(flow, index, enrichedData, statsMap, iocDatabase, networkContext);
            return {
                ...flow,
                heuristic_score: heuristic.score,
                heuristic_level: heuristic.threatLevel,
                heuristic_flags: heuristic.flags,
                heuristic_violations: heuristic.violations,
                is_automated_c2: heuristic.isAutomatedC2 
            };
        });

        
        const sortedData = [...parsedWithHeuristics].sort((a, b) => {
            if (b.heuristic_score !== a.heuristic_score) {
                return b.heuristic_score - a.heuristic_score;
            }
            return (a.avg_interval_seconds > 0 ? a.avg_interval_seconds : 999) - (b.avg_interval_seconds > 0 ? b.avg_interval_seconds : 999);
        });

        
        const knowledgeBaseContent = await loadIOCKnowledgeBase();

        
        const flowsForAI = sortedData.filter(flow => !flow.is_automated_c2).slice(0, 30);
        const dataToAnalyze = JSON.stringify(flowsForAI);

        let aiResponseObject;
        let engineUsed = "REMOTE_BRAIN";
        let codexLastError = null;

        
        const preferredEngine = req?.headers['x-engine'] || 'auto'; 
        const ollamaModel = req?.headers['x-ollama-model'] || 'llama3';
        const codexModel = normalizeCodexModel(req?.headers['x-codex-model'] || CODEX_DEFAULT_MODEL);
        const ollamaUrl = req?.headers['x-ollama-url'] || 'http://localhost:11434';

        
        if (flowsForAI.length > 0) {

            
            
            

            
            if (preferredEngine === 'ollama') {
                engineUsed = 'OLLAMA_LOCAL';
                try {
                    console.log(`[*] Mengirimkan request ke Ollama (${ollamaModel}) di ${ollamaUrl}`);
                    const ollamaPayload = {
                        model: ollamaModel,
                        prompt: `${SYSTEM_PROMPT}\n\n=== RAG THREAT INTELLIGENCE ===\n${knowledgeBaseContent}\n\nData:\n${dataToAnalyze}`,
                        stream: false,
                        format: 'json'
                    };
                    const ollamaResp = await fetch(`${ollamaUrl}/api/generate`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(ollamaPayload)
                    });
                    if (!ollamaResp.ok) throw new Error(`Ollama HTTP ${ollamaResp.status}`);
                    const ollamaData = await ollamaResp.json();
                    let ollamaText = ollamaData.response || ollamaData.message?.content || "{}";
                    if (ollamaText.includes('```json')) ollamaText = ollamaText.split('```json')[1].split('```')[0];
                    aiResponseObject = JSON.parse(ollamaText.trim());
                    console.log(`[+] Ollama (${ollamaModel}) selesai menganalisis.`);
                } catch (ollamaErr) {
                    console.error(`[ERROR] Ollama gagal: ${ollamaErr.message}. Fallback ke Local Engine.`);
                    engineUsed = 'LOCAL_FAST_ENGINE';
                    aiResponseObject = localFallbackAnalysis(parsedWithHeuristics, statsMap, iocDatabase);
                }

            
            } else if (preferredEngine === 'groq') {
                engineUsed = 'CLOUD_FALLBACK';
                try {
                    const groqKey = req?.headers['x-groq-key'] || process.env.GROQ_API_KEY;
                    if (!groqKey) throw new Error('No Groq key');
                    const payload = {
                        model: "llama-3.3-70b-versatile",
                        messages: [
                            { role: "system", content: `${SYSTEM_PROMPT}\n\n=== RAG THREAT INTELLIGENCE ===\n${knowledgeBaseContent}` },
                            { role: "user", content: `Data:\n${dataToAnalyze}` }
                        ],
                        response_format: { type: "json_object" },
                        temperature: 0.2
                    };
                    const groqResp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const groqRem = groqResp.headers.get('x-ratelimit-remaining-requests') || 'N/A';
                    if (!groqResp.ok) throw new Error(`Groq ${groqResp.status}`);
                    const groqData = await groqResp.json();
                    aiResponseObject = JSON.parse(groqData.choices[0].message.content);
                    aiResponseObject.groq_status = { remaining_requests: groqRem };
                    console.log('[+] Groq (forced) selesai menganalisis.');
                } catch (err) {
                    console.error(`[ERROR] Groq forced gagal: ${err.message}. Fallback ke Local.`);
                    engineUsed = 'LOCAL_FAST_ENGINE';
                    aiResponseObject = localFallbackAnalysis(parsedWithHeuristics, statsMap, iocDatabase);
                }

            
            } else if (preferredEngine === 'codex') {
                engineUsed = 'CODEX_CLI';
                try {
                    console.log(`[*] Mengirimkan request ke Codex CLI (model: ${codexModel})...`);
                    const codexPrompt = `${SYSTEM_PROMPT}\n\n=== RAG THREAT INTELLIGENCE ===\n${knowledgeBaseContent}\n\nData:\n${dataToAnalyze}\n\nBALAS HANYA DENGAN JSON MURNI, TANPA MARKDOWN FENCES.`;
                    const { stdout: codexStdout } = await runCodexCli(codexPrompt, codexModel);
                    const codexText = extractJsonPayload(codexStdout);
                    aiResponseObject = JSON.parse(codexText);
                    console.log(`[+] Codex CLI (${codexModel}) selesai menganalisis.`);
                } catch (codexErr) {
                    codexLastError = codexErr.message;
                    console.error(`[ERROR] Codex CLI gagal: ${codexErr.message}. Fallback ke Local Engine.`);
                    engineUsed = 'LOCAL_FAST_ENGINE';
                    aiResponseObject = localFallbackAnalysis(parsedWithHeuristics, statsMap, iocDatabase);
                }

            
            } else if (preferredEngine === 'local') {
                engineUsed = 'LOCAL_FAST_ENGINE';
                aiResponseObject = localFallbackAnalysis(parsedWithHeuristics, statsMap, iocDatabase);

            
            } else {
            
            try {
                console.log(`[*] Mengirimkan request ke Remote Brain (Colab): ${REMOTE_BRAIN_URL}`);
                const promptText = `${SYSTEM_PROMPT}\n\n=== RAG THREAT INTELLIGENCE KNOWLEDGE BASE ===\n${knowledgeBaseContent}\n\nBerikut adalah data koneksi jaringan terfilter untuk dianalisis secara behavioral:\n\n${dataToAnalyze}`;
                
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 15000); 

                const remoteResponse = await fetch(REMOTE_BRAIN_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ prompt: promptText }),
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (!remoteResponse.ok) {
                    throw new Error(`Remote brain status ${remoteResponse.status}`);
                }

                const remoteData = await remoteResponse.json();
                
                let responseText = "";
                if (remoteData.response) {
                    responseText = remoteData.response;
                } else if (typeof remoteData === 'object') {
                    responseText = JSON.stringify(remoteData);
                } else {
                    responseText = remoteData;
                }

                if (responseText.includes("```json")) {
                    responseText = responseText.split("```json")[1].split("```")[0];
                } else if (responseText.includes("```")) {
                    responseText = responseText.split("```")[1].split("```")[0];
                }

                aiResponseObject = JSON.parse(responseText.trim());
                console.log("[+] Berhasil menganalisis menggunakan REMOTE BRAIN (Colab).");
            } catch (remoteErr) {
                console.warn(`[WARNING] Remote Brain (Colab) gagal/timeout (${remoteErr.message}). Mencoba Codex CLI...`);

                
                let codexAutoSuccess = false;
                try {
                    engineUsed = 'CODEX_CLI';
                    console.log(`[*] AUTO: Mencoba Codex CLI (model: ${codexModel})...`);
                    const codexAutoPrompt = `${SYSTEM_PROMPT}\n\n=== RAG THREAT INTELLIGENCE ===\n${knowledgeBaseContent}\n\nData:\n${dataToAnalyze}\n\nBALAS HANYA DENGAN JSON MURNI, TANPA MARKDOWN FENCES.`;
                    const { stdout: codexAutoOut } = await runCodexCli(codexAutoPrompt, codexModel);
                    const codexAutoText = extractJsonPayload(codexAutoOut);
                    aiResponseObject = JSON.parse(codexAutoText);
                    codexAutoSuccess = true;
                    console.log('[+] AUTO: Codex CLI berhasil menganalisis.');
                } catch (codexAutoErr) {
                    codexLastError = codexAutoErr.message;
                    console.warn(`[WARNING] Codex CLI gagal (${codexAutoErr.message}). Failover ke Groq API...`);
                }

                if (!codexAutoSuccess) {
                engineUsed = "CLOUD_FALLBACK";

                try {
                    
                    const groqKey = req?.headers['x-groq-key'] || process.env.GROQ_API_KEY;
                    if (!groqKey) {
                        throw new Error("GROQ_API_KEY tidak dikonfigurasi dan tidak ada di header");
                    }
                    const payload = {
                        model: "llama-3.3-70b-versatile",
                        messages: [
                            {
                                role: "system",
                                content: `${SYSTEM_PROMPT}\n\n=== RAG THREAT INTELLIGENCE KNOWLEDGE BASE ===\n${knowledgeBaseContent}`
                            },
                            {
                                role: "user",
                                content: `Berikut adalah data koneksi jaringan terfilter untuk dianalisis secara behavioral:\n\n${dataToAnalyze}`
                            }
                        ],
                        response_format: { type: "json_object" },
                        temperature: 0.2 
                    };

                    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${groqKey}`,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(payload)
                    });

                    
                    const groqRemainingRequests = response.headers.get('x-ratelimit-remaining-requests') || "N/A";
                    const groqRemainingTokens = response.headers.get('x-ratelimit-remaining-tokens') || "N/A";

                    if (!response.ok) {
                        const errorData = await response.text();
                        throw new Error(`API Error: ${response.status} - ${errorData}`);
                    }

                    const data = await response.json();
                    const aiResponseString = data.choices[0].message.content;
                    aiResponseObject = JSON.parse(aiResponseString);
                    
                    aiResponseObject.groq_status = {
                        remaining_requests: groqRemainingRequests,
                        remaining_tokens: groqRemainingTokens
                    };
                    console.log("[+] Berhasil menganalisis menggunakan CLOUD FALLBACK (Groq).");
                } catch (groqErr) {
                    console.error(`[CRITICAL] Groq API juga gagal (${groqErr.message}). Mengaktifkan Local Deterministic Engine...`);
                    engineUsed = "LOCAL_FAST_ENGINE";
                    aiResponseObject = localFallbackAnalysis(parsedWithHeuristics, statsMap, iocDatabase);
                }
                } 
            } 
            } 
        } 



        if (!aiResponseObject) {
            console.log("[*] Seluruh anomali kritis telah diselesaikan lokal (Bypassed AI). Menggunakan Local Fast Engine...");
            engineUsed = "LOCAL_FAST_ENGINE";
            aiResponseObject = localFallbackAnalysis(parsedWithHeuristics, statsMap, iocDatabase);
        }

        
        
        if (engineUsed !== "LOCAL_FAST_ENGINE") {
            const aiTemuanMap = new Map();
            if (aiResponseObject.temuan && Array.isArray(aiResponseObject.temuan)) {
                aiResponseObject.temuan.forEach(t => {
                    const clean = ip => ip ? ip.trim() : "";
                    const key = `${clean(t.ip_sumber)}->${clean(t.ip_tujuan)}`;
                    const reverseKey = `${clean(t.ip_tujuan)}->${clean(t.ip_sumber)}`;
                    aiTemuanMap.set(key, t);
                    aiTemuanMap.set(reverseKey, t);
                });
            }

            const finalTemuanList = parsedWithHeuristics.map(flow => {
                const clean = ip => ip ? ip.trim() : "";
                const key = `${clean(flow.src_ip)}->${clean(flow.dst_ip)}`;

                
                if (flow.is_automated_c2) {
                    const platform = (flow.avg_ttl || 64) > 90 ? "Windows" : "macOS/Linux";
                    return {
                        ip_sumber: flow.src_ip,
                        ip_tujuan: flow.dst_ip,
                        tingkat_ancaman: "CRITICAL",
                        alasan_teknis: flow.heuristic_violations.join(" | "),
                        rekomendasi_tindakan: "Isolasi host dari jaringan lokal segera. Blokir port C2 pada firewall.",
                        intel_report: {
                            malware_family: "Automated C2 Beaconing",
                            platform_detected: platform,
                            ttp_mapping: "T1071.001 - Application Layer Protocol: Web Protocols",
                            mitre_attack: "T1041 - Exfiltration Over Alternative Protocol",
                            logic_reasoning: flow.heuristic_violations.join(" | "),
                            confidence_score: 100,
                            severity_score: 100,
                            behavior_flags: flow.heuristic_flags,
                            behavior_violations: flow.heuristic_violations,
                            tls_sni: flow.tls_sni_list && flow.tls_sni_list.length > 0 ? flow.tls_sni_list.join(", ") : "",
                            dns_anomaly: flow.dns_query_count > 50 || (flow.unique_dns_domains && flow.unique_dns_domains.length > 10)
                        },
                        raw_metrics: {
                            packet_count: flow.packet_count,
                            avg_interval: flow.avg_interval_seconds,
                            avg_ttl: flow.avg_ttl,
                            protocol: flow.protocol,
                            dst_port: flow.dst_port,
                            tcp_flags: flow.tcp_flags || flow.tcp_flags_str || "NONE",
                            duration_seconds: flow.duration_seconds || 0,
                            bytes_per_packet: flow.packet_count ? Math.round(flow.total_bytes / flow.packet_count) : 0
                        }
                    };
                }

                
                if (aiTemuanMap.has(key)) {
                    const aiItem = aiTemuanMap.get(key);
                    return {
                        ip_sumber: flow.src_ip,
                        ip_tujuan: flow.dst_ip,
                        tingkat_ancaman: aiItem.tingkat_ancaman || flow.heuristic_level,
                        alasan_teknis: aiItem.alasan_teknis || flow.heuristic_violations.join(" | "),
                        rekomendasi_tindakan: aiItem.rekomendasi_tindakan || "Isolasi host dan blokir IP.",
                        intel_report: {
                            malware_family: aiItem.intel_report?.malware_family || flow.heuristic_flags.join(", "),
                            platform_detected: aiItem.intel_report?.platform_detected || (flow.avg_ttl > 90 ? "Windows" : "macOS/Linux"),
                            ttp_mapping: aiItem.intel_report?.ttp_mapping || "T1071.001 - Application Layer Protocol: Web Protocols",
                            mitre_attack: aiItem.intel_report?.mitre_attack || getMitreMapping(flow.heuristic_flags),
                            logic_reasoning: aiItem.intel_report?.logic_reasoning || aiItem.alasan_teknis || flow.heuristic_violations.join(" | "),
                            confidence_score: aiItem.intel_report?.confidence_score || 85,
                            severity_score: aiItem.intel_report?.severity_score || flow.heuristic_score,
                            behavior_flags: aiItem.intel_report?.behavior_flags || flow.heuristic_flags,
                            behavior_violations: aiItem.intel_report?.behavior_violations || flow.heuristic_violations,
                            tls_sni: aiItem.intel_report?.tls_sni || (flow.tls_sni_list && flow.tls_sni_list.length > 0 ? flow.tls_sni_list.join(", ") : ""),
                            dns_anomaly: aiItem.intel_report?.dns_anomaly !== undefined ? aiItem.intel_report.dns_anomaly : (flow.dns_query_count > 50 || (flow.unique_dns_domains && flow.unique_dns_domains.length > 10))
                        },
                        raw_metrics: {
                            packet_count: flow.packet_count,
                            avg_interval: flow.avg_interval_seconds,
                            avg_ttl: flow.avg_ttl,
                            protocol: flow.protocol,
                            dst_port: flow.dst_port,
                            tcp_flags: flow.tcp_flags || flow.tcp_flags_str || "NONE",
                            duration_seconds: flow.duration_seconds || 0,
                            bytes_per_packet: flow.packet_count ? Math.round(flow.total_bytes / flow.packet_count) : 0
                        }
                    };
                } else {
                    
                    const platform = (flow.avg_ttl || 64) > 90 ? "Windows" : "macOS/Linux";
                    return {
                        ip_sumber: flow.src_ip,
                        ip_tujuan: flow.dst_ip,
                        tingkat_ancaman: flow.heuristic_level,
                        alasan_teknis: flow.heuristic_violations.join(" | "),
                        rekomendasi_tindakan: flow.heuristic_level === "CRITICAL" ? "Isolasi host dan blokir port firewall." : "Tidak diperlukan tindakan medis/forensik.",
                        intel_report: {
                            malware_family: flow.heuristic_flags.join(", "),
                            platform_detected: platform,
                            ttp_mapping: flow.heuristic_level === "SAFE" ? "None" : "T1041 - Exfiltration Over Alternative Protocol",
                            mitre_attack: flow.heuristic_level === "SAFE" ? "None" : getMitreMapping(flow.heuristic_flags),
                            logic_reasoning: flow.heuristic_violations.join(" | "),
                            confidence_score: 95,
                            severity_score: flow.heuristic_score,
                            behavior_flags: flow.heuristic_flags,
                            behavior_violations: flow.heuristic_violations,
                            tls_sni: flow.tls_sni_list && flow.tls_sni_list.length > 0 ? flow.tls_sni_list.join(", ") : "",
                            dns_anomaly: flow.dns_query_count > 50 || (flow.unique_dns_domains && flow.unique_dns_domains.length > 10)
                        },
                        raw_metrics: {
                            packet_count: flow.packet_count,
                            avg_interval: flow.avg_interval_seconds,
                            avg_ttl: flow.avg_ttl,
                            protocol: flow.protocol,
                            dst_port: flow.dst_port,
                            tcp_flags: flow.tcp_flags || flow.tcp_flags_str || "NONE",
                            duration_seconds: flow.duration_seconds || 0,
                            bytes_per_packet: flow.packet_count ? Math.round(flow.total_bytes / flow.packet_count) : 0
                        }
                    };
                }
            });

            aiResponseObject.temuan = finalTemuanList;
        }

        
        let overallStatus = "SAFE";
        let hasCritical = false;
        let hasSuspicious = false;

        if (aiResponseObject.temuan && Array.isArray(aiResponseObject.temuan)) {
            aiResponseObject.temuan.forEach(t => {
                const lvl = t.tingkat_ancaman ? t.tingkat_ancaman.toUpperCase() : "SAFE";
                if (lvl === "CRITICAL") hasCritical = true;
                else if (lvl === "SUSPICIOUS") hasSuspicious = true;
            });
        }

        if (hasCritical) {
            overallStatus = "CRITICAL";
        } else if (hasSuspicious) {
            overallStatus = "SUSPICIOUS";
        }

        aiResponseObject.status_keseluruhan = overallStatus;

        if (!aiResponseObject.groq_status) {
            aiResponseObject.groq_status = {
                remaining_requests: "N/A",
                remaining_tokens: "N/A"
            };
        }

        if (codexLastError) {
            aiResponseObject.codex_error = codexLastError;
        }

        if (isTruncated) {
            aiResponseObject.warning = "Data dipotong hingga 200 flow pertama untuk efisiensi sistem.";
        }

        
        const threatStats = {
            total_flows: aiResponseObject.temuan?.length || 0,
            critical_count: 0,
            suspicious_count: 0,
            safe_count: 0,
            top_threats: [],
            unique_external_ips: new Set(),
            malware_families_detected: new Set()
        };

        aiResponseObject.temuan?.forEach(t => {
            const lvl = (t.tingkat_ancaman || "SAFE").toUpperCase();
            if (lvl === "CRITICAL") threatStats.critical_count++;
            else if (lvl === "SUSPICIOUS") threatStats.suspicious_count++;
            else threatStats.safe_count++;
            
            if (lvl !== "SAFE" && t.ip_tujuan) {
                threatStats.unique_external_ips.add(t.ip_tujuan);
            }
            if (t.intel_report?.malware_family && 
                t.intel_report.malware_family !== "Clean Traffic" &&
                t.intel_report.malware_family !== "Clean Traffic (Trusted CDN/Infra)") {
                threatStats.malware_families_detected.add(t.intel_report.malware_family);
            }
            if (lvl === "CRITICAL") {
                threatStats.top_threats.push({
                    src: t.ip_sumber,
                    dst: t.ip_tujuan,
                    family: t.intel_report?.malware_family,
                    score: t.intel_report?.severity_score
                });
            }
        });

        aiResponseObject.threat_summary = {
            ...threatStats,
            unique_external_ips: threatStats.unique_external_ips.size,
            malware_families_detected: [...threatStats.malware_families_detected],
            top_threats: threatStats.top_threats
                .sort((a,b) => (b.score||0) - (a.score||0))
                .slice(0, 5)
        };

        
        try {
            await fs.unlink(pcapFilePath);
            console.log(`[*] Cleaned up: ${pcapFilePath}`);
        } catch (e) {  }

        aiResponseObject.engine_used = engineUsed;
        aiResponseObject.network_context = networkContext;
        aiResponseObject.scanned_file = path.basename(pcapFilePath);
        res.json(aiResponseObject);

    } catch (error) {
        console.error("[ERROR] Analisis gagal:", error.message);
        res.status(500).json({ error: "Terjadi kesalahan internal saat menganalisis data jaringan.", detail: error.message });
    }
}


app.post('/api/upload', upload.single('pcapFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "Mohon unggah file PCAP terlebih dahulu." });
    }
    const pcapFilePath = req.file.path;
    await processAndAnalyze(pcapFilePath, res, req);
});


app.get('/api/analyze', async (req, res) => {
    await processAndAnalyze('uji_coba.pcap', res, req);
});

app.get('/api/health', async (req, res) => {
    let codexInstalled = false;
    try {
        await execFileAsync('codex', ['--version'], { timeout: 2000 });
        codexInstalled = true;
    } catch (err) {
        codexInstalled = false;
    }

    res.json({
        status: "ok",
        version: "2.1.0",
        engine: "The Eye C2 Hunter",
        groq_configured: !!process.env.GROQ_API_KEY,
        codex_configured: codexInstalled,
        codex_exec_probe: "/api/codex-status?probe=1",
        remote_brain: REMOTE_BRAIN_URL,
        timestamp: new Date().toISOString()
    });
});


app.get('/api/codex-status', async (req, res) => {
    try {
        const { stdout, stderr } = await execFileAsync('codex', ['--version'], { timeout: 5000 });
        const version = `${stdout}${stderr ? `\n${stderr}` : ''}`.trim();
        const shouldProbeExec = ['1', 'true', 'exec'].includes(String(req.query.probe || '').toLowerCase());

        if (!shouldProbeExec) {
            res.json({
                status: 'ok',
                version,
                exec_status: 'not_probed',
                note: 'codex --version berhasil; gunakan /api/codex-status?probe=1 untuk uji codex exec penuh.'
            });
            return;
        }

        try {
            const probeModel = normalizeCodexModel(req.query.model || CODEX_DEFAULT_MODEL);
            const { stdout: probeStdout } = await runCodexCli(
                'Return only this JSON object and no markdown: {"codex_probe":true}',
                probeModel,
                { timeout: 30000, maxBuffer: 1024 * 1024 }
            );
            JSON.parse(extractJsonPayload(probeStdout));
            res.json({ status: 'ok', version, exec_status: 'ok', model: probeModel });
        } catch (probeErr) {
            res.json({
                status: 'error',
                version,
                exec_status: 'error',
                error: `codex exec failed: ${probeErr.message}`
            });
        }
    } catch (err) {
        res.json({
            status: 'error',
            exec_status: 'unavailable',
            error: 'codex-cli not installed or not in PATH',
            detail: err.message
        });
    }
});


app.get('/api/ollama-models', async (req, res) => {
    const ollamaUrl = req.query.url || 'http://localhost:11434';
    try {
        const resp = await fetch(`${ollamaUrl}/api/tags`);
        if (!resp.ok) throw new Error(`Ollama not reachable (HTTP ${resp.status})`);
        const data = await resp.json();
        const models = (data.models || []).map(m => m.name);
        res.json({ status: 'ok', models, ollama_url: ollamaUrl });
    } catch (err) {
        res.json({ status: 'error', models: [], error: err.message });
    }
});

app.get('/api/enricher-status', (req, res) => {
    res.json(enricher.getStatus());
});

app.listen(PORT, async () => {
    console.log(`[*] Node.js API Relay berjalan di http://localhost:${PORT}`);
    await enricher.initialize();
});
