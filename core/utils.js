'use strict';

function clamp(value, min = 0, max = 100) {
  const n = Number.isFinite(value) ? value : 0;
  return Math.max(min, Math.min(max, n));
}

function mean(values) {
  const nums = values.filter(Number.isFinite);
  if (!nums.length) return 0;
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

function stddev(values) {
  const nums = values.filter(Number.isFinite);
  if (nums.length < 2) return 0;
  const avg = mean(nums);
  const variance = nums.reduce((sum, n) => sum + Math.pow(n - avg, 2), 0) / nums.length;
  return Math.sqrt(variance);
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function toArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === 'object') return Object.keys(value);
  return [String(value)];
}

function shannonEntropy(input) {
  const str = String(input || '');
  if (!str.length) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function normalizeFlow(flow = {}) {
  const packets = safeNumber(flow.packet_count, 0);
  const bytes = safeNumber(flow.total_bytes, 0);
  const duration = safeNumber(flow.duration_seconds, 0);
  const interval = safeNumber(flow.avg_interval_seconds, 0);
  const txBytes = safeNumber(flow.tx_bytes, bytes);
  const rxBytes = safeNumber(flow.rx_bytes, 1) || 1;
  const bytesPerPacket = packets > 0 ? bytes / packets : 0;
  const throughput = duration > 0 ? bytes / duration : 0;
  const outboundRatio = txBytes / rxBytes;
  const sniList = toArray(flow.tls_sni_list);
  const httpUri = flow.http_uri || flow.uri || flow.request_uri || '';

  return {
    srcIp: flow.src_ip || '',
    dstIp: flow.dst_ip || '',
    dstPort: safeNumber(String(flow.dst_port || '0').match(/\d+/)?.[0], 0),
    protocol: String(flow.protocol || '').toUpperCase(),
    packets,
    bytes,
    duration,
    interval,
    txBytes,
    rxBytes,
    bytesPerPacket,
    throughput,
    outboundRatio,
    tcpFlags: String(flow.tcp_flags || flow.tcp_flags_str || ''),
    sniList,
    httpUri,
    domain: flow.resolved_domain || flow.domain || flow.hostname || '',
    asnOrg: flow.enrichment?.asn_org || '',
    asnCountry: flow.enrichment?.asn_country || '',
    iocFeedHit: Boolean(flow.enrichment?.ioc_feed_hit),
    autoTrusted: Boolean(flow.enrichment?.auto_trusted),
    heuristicScore: safeNumber(flow.heuristic_score, 0),
    heuristicFlags: toArray(flow.heuristic_flags),
    heuristicViolations: toArray(flow.heuristic_violations)
  };
}

function entityKey(flow) {
  const f = normalizeFlow(flow);
  return `${f.srcIp}->${f.dstIp}:${f.dstPort}`;
}

module.exports = {
  clamp,
  mean,
  stddev,
  safeNumber,
  toArray,
  shannonEntropy,
  normalizeFlow,
  entityKey
};
