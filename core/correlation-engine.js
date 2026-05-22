'use strict';

const { normalizeFlow, clamp } = require('./utils');

class CorrelationEngine {
  analyze(flow, context = {}) {
    const f = normalizeFlow(flow);
    const flags = new Set(f.heuristicFlags || []);
    const violations = [];
    let score = 0;

    const hasBeacon = [...flags].some(x => /beacon|polling|cadence|low-and-slow/i.test(x));
    const hasRare = flags.has('Rare External Endpoint') || context.baseline?.flags?.includes('Baseline: New or Immature Entity');
    const hasTlsAnomaly = flags.has('TLS Anomaly') || f.sniList.length === 0 && f.dstPort === 443;
    const hasExfil = [...flags].some(x => /exfil|outbound|upload/i.test(x)) || f.outboundRatio > 5;
    const hasHighEntropy = [...flags].some(x => /entropy|obfuscated|encrypted/i.test(x));
    const hasBadReputation = context.reputation?.score >= 20;
    const hasIoc = f.iocFeedHit || [...flags].some(x => /ioc|ti feed/i.test(x));
    const hasSuspiciousPort = ![53, 80, 443, 123, 22, 25, 465, 587].includes(f.dstPort) && f.dstPort > 0;

    const signals = [
      ['beaconing', hasBeacon],
      ['rare_endpoint', hasRare],
      ['tls_anomaly', hasTlsAnomaly],
      ['exfil_bias', hasExfil],
      ['high_entropy', hasHighEntropy],
      ['bad_reputation', hasBadReputation],
      ['ioc_context', hasIoc],
      ['suspicious_port', hasSuspiciousPort]
    ].filter(([, active]) => active).map(([name]) => name);

    if (signals.length >= 2) {
      score += 15 + signals.length * 7;
      violations.push(`Correlation Graph: ${signals.length} sinyal independen aktif (${signals.join(', ')}).`);
    }

    if (hasBeacon && hasRare && (hasTlsAnomaly || hasSuspiciousPort)) {
      score += 30;
      violations.push('Confidence Graph: beaconing + rare endpoint + TLS/port anomaly membentuk pola kuat C2 framework.');
    }

    if (hasExfil && hasHighEntropy && (hasRare || hasBadReputation)) {
      score += 28;
      violations.push('Confidence Graph: exfil bias + entropy tinggi + rare/reputation context mengarah ke data theft channel.');
    }

    if (hasIoc && (hasBeacon || hasExfil || hasBadReputation)) {
      score += 35;
      violations.push('IOC Correlation: indikator intel tidak berdiri sendiri; ada dukungan perilaku/riwayat sehingga confidence dinaikkan.');
    }

    return {
      score: clamp(score, 0, 80),
      signals,
      flags: signals.length ? ['Correlated Confidence Graph'] : [],
      violations
    };
  }
}

module.exports = CorrelationEngine;
