# Adaptive Detection Engine

Layer ini mengubah PcapAnalyzer dari static heuristic biasa menjadi adaptive detection pipeline.

## Komponen

- `baseline-engine.js`  
  Belajar pola normal endpoint/domain/ASN: interval, bytes, packet count, durasi, jam aktif, dan port.

- `reputation-engine.js`  
  Menyimpan memory entity: first seen, last seen, detections, anomaly count, clean count, confidence trend, port/domain/ASN history.

- `correlation-engine.js`  
  Menggabungkan sinyal yang berdiri sendiri menjadi confidence graph: beaconing + rare endpoint + TLS anomaly + exfil bias + IOC context.

- `scoring-engine.js`  
  Mengubah score statis menjadi dynamic score dengan multiplier: rarity, temporal drift, entropy, correlation, dan trust discount.

- `reasoning-engine.js`  
  Membuat hypothesis layer: likely C2, stealer exfiltration, RAT/backdoor, atau known-threat infra.

- `adaptive-engine.js`  
  Orchestrator utama untuk menjalankan semua layer di atas.

## Integrasi ke `server.js`

Tambahkan import di bagian atas:

```js
const adaptiveEngine = require('./core/adaptive-engine');
```

Lalu setelah `parsedWithHeuristics` dibuat, tambahkan:

```js
const parsedWithAdaptive = await adaptiveEngine.analyze(parsedWithHeuristics);
```

Kemudian ganti sorting dari:

```js
const sortedData = [...parsedWithHeuristics].sort((a, b) => {
  if (b.heuristic_score !== a.heuristic_score) {
    return b.heuristic_score - a.heuristic_score;
  }
  return (a.avg_interval_seconds > 0 ? a.avg_interval_seconds : 999) - (b.avg_interval_seconds > 0 ? b.avg_interval_seconds : 999);
});
```

menjadi:

```js
const sortedData = [...parsedWithAdaptive].sort((a, b) => {
  const scoreA = a.adaptive?.score ?? a.heuristic_score ?? 0;
  const scoreB = b.adaptive?.score ?? b.heuristic_score ?? 0;
  if (scoreB !== scoreA) return scoreB - scoreA;
  return (a.avg_interval_seconds > 0 ? a.avg_interval_seconds : 999) -
         (b.avg_interval_seconds > 0 ? b.avg_interval_seconds : 999);
});
```

Dan di object flow hasil map, tambahkan field ini agar UI/API bisa membaca reasoning:

```js
adaptive_score: flow.adaptive?.score,
adaptive_level: flow.adaptive?.level,
adaptive_flags: flow.adaptive?.flags || [],
adaptive_violations: flow.adaptive?.violations || [],
adaptive_reasoning: flow.adaptive?.reasoning || null,
```

## Cara kerja pipeline baru

```text
FLOW
 ↓
ENRICHMENT
 ↓
STATIC HEURISTIC
 ↓
BASELINE COMPARISON
 ↓
REPUTATION MEMORY
 ↓
CONFIDENCE GRAPH CORRELATION
 ↓
DYNAMIC SCORING
 ↓
THREAT REASONING
 ↓
VERDICT
```

## Catatan penting

- Engine ini tidak membutuhkan dependency baru.
- State disimpan di `brain/cache/adaptive_baseline.json` dan `brain/cache/entity_reputation.json`.
- Hasil pertama mungkin masih banyak `Baseline: New or Immature Entity` karena engine baru mulai belajar.
- Setelah beberapa PCAP dianalisis, baseline dan reputation mulai lebih akurat.
