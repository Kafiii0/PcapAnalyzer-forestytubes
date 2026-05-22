'use strict';

/**
 * adaptive-start.js
 * Starter tunggal The Eye.
 * Fokus: jalankan adaptive engine + harden tombol upload agar File Explorer selalu terbuka.
 */

const fs = require('fs');
const path = require('path');
const Module = require('module');

const ROOT = __dirname;
const SERVER_PATH = path.join(ROOT, 'server.js');
const INDEX_PATH = path.join(ROOT, 'index.html');
const IOC_FILE = path.join(ROOT, 'brain', 'knowledge', 'ioc_threat_intel.txt');

const DEMON_EYE_CSS = `

        /* Demon Eye UI Upgrade */
        .demon-eye-wrap{width:56px;height:56px;display:flex;align-items:center;justify-content:center;filter:drop-shadow(0 0 14px rgba(220,38,38,.75));}
        .demon-eye{position:relative;width:50px;height:30px;transform:rotate(45deg);border-radius:0 100% 0 100%;overflow:hidden;background:radial-gradient(circle at center,rgba(127,0,0,.95),rgba(20,0,0,1) 62%,#020202 100%);border:1.5px solid rgba(248,113,113,.95);box-shadow:0 0 10px rgba(239,68,68,.9),0 0 24px rgba(220,38,38,.55),inset 0 0 13px rgba(255,0,0,.35);animation:demonEyeFloat 3.2s ease-in-out infinite;}
        .eye-inner{position:absolute;inset:4px;border-radius:50%;transform:rotate(-45deg);display:flex;align-items:center;justify-content:center;background:radial-gradient(circle,#250000 0%,#080000 66%,#000 100%);}
        .iris{position:absolute;width:24px;height:24px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#ffd1d1 0%,#ff4b4b 14%,#dc2626 38%,#7f0000 68%,#1a0000 100%);box-shadow:0 0 12px rgba(255,0,0,.95),0 0 26px rgba(220,38,38,.55),inset 0 0 8px rgba(255,255,255,.12);animation:demonIrisPulse 1.8s ease-in-out infinite;}
        .pupil{position:absolute;width:5px;height:20px;border-radius:999px;background:#020202;box-shadow:0 0 7px #000;}
        .eye-glow{position:absolute;width:40px;height:40px;border-radius:50%;background:radial-gradient(circle,rgba(255,0,0,.25),transparent 70%);filter:blur(4px);animation:demonGlowPulse 2s ease-in-out infinite;}
        .eye-shine{position:absolute;top:6px;left:17px;width:5px;height:5px;border-radius:50%;background:rgba(255,255,255,.95);filter:blur(.5px);}
        .eyelid{position:absolute;left:-10%;width:120%;height:55%;background:linear-gradient(to bottom,#050505,rgba(45,0,0,.98));z-index:5;transition:transform .14s ease-in-out;}
        .eyelid-top{top:-38%;border-bottom:1px solid rgba(239,68,68,.55);transform-origin:center bottom;}
        .eyelid-bottom{bottom:-38%;border-top:1px solid rgba(239,68,68,.55);transform-origin:center top;}
        .demon-eye.blink .eyelid-top{transform:translateY(72%);}
        .demon-eye.blink .eyelid-bottom{transform:translateY(-72%);}
        @keyframes demonIrisPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.12)}}
        @keyframes demonGlowPulse{0%,100%{opacity:.55;transform:scale(1)}50%{opacity:1;transform:scale(1.12)}}
        @keyframes demonEyeFloat{0%,100%{transform:rotate(45deg) translateY(0)}50%{transform:rotate(45deg) translateY(-2px)}}
`;

const DEMON_EYE_HTML = `
            <div class="demon-eye-wrap" aria-label="The Eye scanner">
                <div class="demon-eye" id="demonEye"><div class="eye-inner"><div class="iris"></div><div class="pupil"></div><div class="eye-glow"></div><div class="eye-shine"></div></div><div class="eyelid eyelid-top"></div><div class="eyelid eyelid-bottom"></div></div>
            </div>`;

const DEMON_EYE_JS = `
<script>
(function(){const eye=document.getElementById('demonEye');if(!eye)return;function blink(d){eye.classList.add('blink');setTimeout(()=>eye.classList.remove('blink'),d||160)}function loop(){setTimeout(()=>{blink(120+Math.random()*110);if(Math.random()>.68)setTimeout(()=>blink(110),170);loop()},1300+Math.random()*2600)}setTimeout(()=>blink(150),700);loop();})();
</script>`;

const UPLOAD_FIX_JS = `
<script>
// upload chooser hardening
(function(){
  function bindUploadChooser(){
    const input=document.getElementById('fileInput');
    const small=document.getElementById('btnSmallUpload');
    const drop=document.getElementById('dropZone');
    if(!input)return;
    input.removeAttribute('disabled');
    input.accept='.pcap,.pcapng';
    input.style.pointerEvents='auto';
    function openPicker(e){
      if(e){e.preventDefault();e.stopPropagation();}
      try{input.click();}catch(err){console.error('[upload-fix] gagal membuka file picker',err);}
    }
    if(small && small.dataset.uploadFix!=='1'){
      small.dataset.uploadFix='1';
      small.setAttribute('role','button');
      small.setAttribute('tabindex','0');
      small.addEventListener('click',openPicker,true);
      small.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){openPicker(e);}},true);
    }
    if(drop && drop.dataset.uploadFix!=='1'){
      drop.dataset.uploadFix='1';
      drop.addEventListener('click',openPicker,true);
    }
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bindUploadChooser);else bindUploadChooser();
  setTimeout(bindUploadChooser,500);
})();
</script>`;

function ensureLocalFiles() {
  fs.mkdirSync(path.dirname(IOC_FILE), { recursive: true });
  if (!fs.existsSync(IOC_FILE)) fs.writeFileSync(IOC_FILE, '# Local IOC file\n# Tambahkan IP/domain manual di sini jika dibutuhkan.\n');
}

function patchIndexFile() {
  if (!fs.existsSync(INDEX_PATH)) return;
  let html = fs.readFileSync(INDEX_PATH, 'utf-8');
  let changed = false;

  if (!html.includes('Demon Eye UI Upgrade')) {
    html = html.replace('</style>', `${DEMON_EYE_CSS}\n    </style>`);
    changed = true;
  }

  if (!html.includes('id="demonEye"')) {
    html = html.replace(/\s*<div\s+class="blinking-eye[\s\S]*?<div\s+class="w-4 h-4[\s\S]*?<\/div>\s*<\/div>/, `\n${DEMON_EYE_HTML}`);
    changed = true;
  }

  // Native fallback: jadikan tombol header sebagai label file input.
  if (!html.includes('upload-native-label-fallback')) {
    html = html.replace(
      /<button id="btnSmallUpload"([\s\S]*?)>/,
      '<label for="fileInput" id="btnSmallUpload" data-upload-native="1"$1><!-- upload-native-label-fallback -->'
    );
    html = html.replace(
      /PILIH FILE PCAP\s*<\/button>/,
      'PILIH FILE PCAP\n            </label>'
    );
    changed = true;
  }

  if (!html.includes('upload chooser hardening')) {
    html = html.replace('</body>', `${UPLOAD_FIX_JS}\n</body>`);
    changed = true;
  }

  if (!html.includes('const eye=document.getElementById')) {
    html = html.replace('</body>', `${DEMON_EYE_JS}\n</body>`);
    changed = true;
  }

  if (changed) {
    fs.writeFileSync(INDEX_PATH, html);
    console.log('[adaptive-start] index.html upload/UI patched');
  }
}

function patchServerSource(source) {
  let code = source;

  if (!code.includes("require('./core/adaptive-engine')")) {
    code = code.replace("const enricher = require('./enricher');", "const enricher = require('./enricher');\nconst adaptiveEngine = require('./core/adaptive-engine');");
  }

  if (!code.includes('const parsedWithAdaptive = await adaptiveEngine.analyze(parsedWithHeuristics);')) {
    const marker = '        // Urutkan berdasarkan severity score terbesar ke terkecil';
    if (!code.includes(marker)) throw new Error('Marker sorting tidak ditemukan.');
    code = code.replace(marker, `        // Adaptive Detection Layer: baseline + memory + confidence graph + dynamic scoring + reasoning\n        const parsedWithAdaptive = await adaptiveEngine.analyze(parsedWithHeuristics);\n\n        // Urutkan berdasarkan adaptive severity score terbesar ke terkecil`);
  }

  const oldSort = `        const sortedData = [...parsedWithHeuristics].sort((a, b) => {\n            if (b.heuristic_score !== a.heuristic_score) {\n                return b.heuristic_score - a.heuristic_score;\n            }\n            return (a.avg_interval_seconds > 0 ? a.avg_interval_seconds : 999) - (b.avg_interval_seconds > 0 ? b.avg_interval_seconds : 999);\n        });`;
  const newSort = `        const sortedData = [...parsedWithAdaptive].sort((a, b) => {\n            const scoreA = a.adaptive?.score ?? a.heuristic_score ?? 0;\n            const scoreB = b.adaptive?.score ?? b.heuristic_score ?? 0;\n            if (scoreB !== scoreA) return scoreB - scoreA;\n            return (a.avg_interval_seconds > 0 ? a.avg_interval_seconds : 999) - (b.avg_interval_seconds > 0 ? b.avg_interval_seconds : 999);\n        });`;
  code = code.replace(oldSort, newSort);

  code = code.replace(/localFallbackAnalysis\(parsedWithHeuristics/g, 'localFallbackAnalysis(parsedWithAdaptive');
  code = code.replace('const finalTemuanList = parsedWithHeuristics.map(flow => {', 'const finalTemuanList = parsedWithAdaptive.map(flow => {');
  code = code.replace(/severity_score: flow\.heuristic_score/g, 'severity_score: flow.adaptive?.score ?? flow.heuristic_score');
  code = code.replace(/confidence_score: 100/g, 'confidence_score: heuristic.confidence || flow.adaptive?.score || 85');
  code = code.replace(/confidence_score: 95/g, 'confidence_score: flow.adaptive?.score ?? heuristic.confidence ?? 85');
  code = code.replace(/tingkat_ancaman: flow\.heuristic_level/g, 'tingkat_ancaman: flow.adaptive?.level ?? flow.heuristic_level');
  code = code.replace(/Indikasi eksfiltrasi data aktif\./g, 'Indikasi kanal outbound mencurigakan; perlu validasi payload sebelum disebut eksfiltrasi aktif.');
  code = code.replace(/False positive sangat tidak mungkin pada kondisi ini\./g, 'Confidence meningkat karena beberapa sinyal berkorelasi; tetap perlu validasi host, payload, dan konteks aplikasi.');
  code = code.replace(/Exfil Traffic Bias/g, 'Suspicious Outbound Bias');
  code = code.replace(/Data Exfiltration Endpoint/g, 'Suspicious Data Transfer Endpoint');

  if (!code.includes('attachAdaptiveReports')) {
    const attachBlock = `        // Attach adaptive report and family matrix into final API results
        const attachAdaptiveReports = () => {
            const adaptiveMap = new Map();
            parsedWithAdaptive.forEach(flow => {
                const clean = ip => ip ? ip.trim() : "";
                adaptiveMap.set(clean(flow.src_ip) + "->" + clean(flow.dst_ip), flow.adaptive);
                adaptiveMap.set(clean(flow.dst_ip) + "->" + clean(flow.src_ip), flow.adaptive);
            });
            if (aiResponseObject.temuan && Array.isArray(aiResponseObject.temuan)) {
                aiResponseObject.temuan = aiResponseObject.temuan.map(t => {
                    const clean = ip => ip ? ip.trim() : "";
                    const adaptive = adaptiveMap.get(clean(t.ip_sumber) + "->" + clean(t.ip_tujuan));
                    if (!adaptive) return t;
                    const topFamily = adaptive.family_matrix?.topFamily;
                    const topPercent = adaptive.family_matrix?.topPercent || 0;
                    const currentIntel = t.intel_report || {};
                    const familyName = topPercent >= 50 && topFamily ? topFamily + " (" + topPercent + "% match)" : (currentIntel.malware_family || "Unknown");
                    return {
                        ...t,
                        adaptive_report: adaptive,
                        intel_report: {
                            ...currentIntel,
                            malware_family: familyName,
                            family_matrix: adaptive.family_matrix
                        }
                    };
                });
            }
        };
        attachAdaptiveReports();

`;
    code = code.replace('        // Tentukan status keseluruhan secara dinamis berdasarkan seluruh temuan gabungan aktual', attachBlock + '        // Tentukan status keseluruhan secara dinamis berdasarkan seluruh temuan gabungan aktual');
  }

  if (!code.includes('aiResponseObject.adaptive_engine')) {
    code = code.replace('        aiResponseObject.status_keseluruhan = overallStatus;\n', `        aiResponseObject.status_keseluruhan = overallStatus;\n\n        aiResponseObject.adaptive_engine = {\n            enabled: true,\n            pipeline: ['baseline', 'reputation_memory', 'confidence_graph', 'dynamic_scoring', 'threat_reasoning', 'family_signature_matrix'],\n            note: 'Adaptive score dan family matrix ikut dipakai untuk severity dan penjelasan family malware.'\n        };\n`);
  }

  if (!code.includes('const parsedWithAdaptive = await adaptiveEngine.analyze(parsedWithHeuristics);')) throw new Error('Patch adaptive gagal.');
  return code;
}

function runPatchedServer() {
  const source = fs.readFileSync(SERVER_PATH, 'utf-8');
  const patchedSource = patchServerSource(source);
  const serverModule = new Module(SERVER_PATH, module.parent);
  serverModule.filename = SERVER_PATH;
  serverModule.paths = Module._nodeModulePaths(ROOT);
  serverModule._compile(patchedSource, SERVER_PATH);
}

try {
  ensureLocalFiles();
  patchIndexFile();
  runPatchedServer();
} catch (err) {
  console.error('[adaptive-start] Failed to start:', err);
  process.exit(1);
}
