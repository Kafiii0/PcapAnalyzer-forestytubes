'use strict';

const { normalizeFlow, clamp } = require('./utils');

function textOf(flow, layers = {}) {
  const f = normalizeFlow(flow);
  return [
    f.httpUri,
    f.domain,
    f.sniList.join(' '),
    f.heuristicFlags.join(' '),
    f.heuristicViolations.join(' '),
    layers.correlation?.signals?.join(' '),
    layers.reasoning?.hypothesis,
    layers.reasoning?.possibleFamilies?.join(' ')
  ].filter(Boolean).join(' | ').toLowerCase();
}

function hasEncodedQuery(uri = '') {
  return /\?.{35,}/.test(uri) || /[?&][a-zA-Z]{1,4}=[A-Za-z0-9+/=_-]{30,}/.test(uri);
}

function hasShortRandomPath(uri = '') {
  return /^\/[a-z0-9]{3,14}\/?(\?|$)/i.test(uri);
}

function hasSuspiciousPost(flow = {}) {
  const method = String(flow.http_method || flow.method || '').toUpperCase();
  const uri = String(flow.http_uri || flow.uri || flow.request_uri || '');
  return method === 'POST' || /post\s+/i.test(String(flow.http_request || '')) || /^\/[a-z0-9]{3,14}\/?$/i.test(uri);
}

class FamilySignatureEngine {
  constructor() {
    this.signatures = [
      {
        family: 'XLoader/Formbook',
        description: 'Info-stealer family dengan HTTP C2/check-in, encoded query, dan banyak post-infection domains.',
        checks: [
          { id: 'http_c2', label: 'HTTP C2/check-in traffic', weight: 18, test: (flow, layers, f, t) => f.dstPort === 80 || /http|c2|check-in|checkin|post-infection/.test(t) },
          { id: 'encoded_query', label: 'Encoded/long query parameter', weight: 22, test: (flow, layers, f) => hasEncodedQuery(f.httpUri) },
          { id: 'short_path', label: 'Short/random URI path', weight: 16, test: (flow, layers, f) => hasShortRandomPath(f.httpUri) },
          { id: 'post_channel', label: 'POST or staged HTTP exchange', weight: 16, test: (flow, layers, f) => hasSuspiciousPost(flow) || /post|staged|outbound bias/.test(textOf(flow, layers)) },
          { id: 'many_domains', label: 'Multiple rare external domains/endpoints', weight: 14, test: (flow, layers, f, t) => /rare endpoint|rare_external|new or immature|fan-out|many domains/.test(t) },
          { id: 'stealer_context', label: 'Stealer/form grabber context', weight: 14, test: (flow, layers, f, t) => /xloader|formbook|stealer|credential|browser|wallet/.test(t) }
        ]
      },
      {
        family: 'Cobalt Strike/Beacon',
        description: 'C2 beacon dengan sleep interval, jitter rendah, cadence konsisten, dan TLS/HTTP control channel.',
        checks: [
          { id: 'low_jitter', label: 'Low jitter beacon interval', weight: 24, test: (flow, layers, f, t) => /low jitter|sleep beacon|beaconing/.test(t) },
          { id: 'regular_cadence', label: 'Consistent packet cadence', weight: 18, test: (flow, layers, f, t) => /cadence|consistent packet/.test(t) },
          { id: 'long_duration', label: 'Long-lived or periodic session', weight: 16, test: (flow, layers, f) => f.duration > 300 && f.packets > 10 },
          { id: 'http_tls_c2', label: 'HTTP/TLS C2 transport', weight: 14, test: (flow, layers, f) => [80, 443].includes(f.dstPort) },
          { id: 'rare_infra', label: 'Rare/non-trusted external infra', weight: 14, test: (flow, layers, f, t) => /rare endpoint|new or immature|tls anomaly/.test(t) },
          { id: 'framework_context', label: 'C2 framework context', weight: 14, test: (flow, layers, f, t) => /cobalt|sliver|havoc|mythic|generic c2/.test(t) }
        ]
      },
      {
        family: 'AsyncRAT/NjRAT/QuasarRAT',
        description: 'RAT/backdoor dengan keep-alive, port non-standar, traffic interaktif, atau channel kontrol persisten.',
        checks: [
          { id: 'rat_port', label: 'RAT/backdoor-like port', weight: 24, test: (flow, layers, f) => new Set([5000,5001,8888,9999,1337,31337,4444,4445]).has(f.dstPort) },
          { id: 'keepalive', label: 'Keep-alive / low-and-slow channel', weight: 18, test: (flow, layers, f, t) => /keepalive|low-and-slow|lifecycle|dormant/.test(t) },
          { id: 'persistent', label: 'Persistent session duration', weight: 16, test: (flow, layers, f) => f.duration > 600 && f.packets > 15 },
          { id: 'nonstandard', label: 'Non-standard external service', weight: 16, test: (flow, layers, f) => f.dstPort > 0 && ![53,80,123,443,25,465,587].includes(f.dstPort) },
          { id: 'rat_context', label: 'RAT family/context detected', weight: 16, test: (flow, layers, f, t) => /rat|asyncrat|njrat|quasar|dcrat|backdoor/.test(t) },
          { id: 'rare_remote', label: 'Rare remote endpoint', weight: 10, test: (flow, layers, f, t) => /rare endpoint|first seen|new or immature/.test(t) }
        ]
      },
      {
        family: 'Generic InfoStealer',
        description: 'Credential/browser/wallet stealer dengan outbound bias, entropy tinggi, dan telemetry/upload endpoint.',
        checks: [
          { id: 'outbound_bias', label: 'Suspicious outbound bias', weight: 20, test: (flow, layers, f, t) => f.outboundRatio > 5 || /outbound bias|exfil/.test(t) },
          { id: 'high_entropy', label: 'High entropy / obfuscated payload', weight: 18, test: (flow, layers, f, t) => /entropy|obfuscated|encoded/.test(t) },
          { id: 'credential_terms', label: 'Credential/browser/wallet terms', weight: 18, test: (flow, layers, f, t) => /credential|browser|wallet|messenger|stealer/.test(t) },
          { id: 'upload_submit', label: 'Upload/submit/send endpoint', weight: 16, test: (flow, layers, f) => /upload|submit|send|gate|panel|log|info/i.test(f.httpUri) },
          { id: 'public_destination', label: 'Public destination endpoint', weight: 12, test: (flow, layers, f) => Boolean(f.dstIp) && !/^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(f.dstIp) },
          { id: 'rare_or_ioc', label: 'Rare endpoint or IOC context', weight: 16, test: (flow, layers, f, t) => f.iocFeedHit || /ioc|rare endpoint|first seen/.test(t) }
        ]
      },
      {
        family: 'DNS Tunneling/DGA',
        description: 'DNS-based C2/tunneling dengan query volume tinggi, domain acak, atau DNS anomaly.',
        checks: [
          { id: 'dns_port', label: 'DNS transport/port 53', weight: 20, test: (flow, layers, f) => f.dstPort === 53 || f.protocol === 'DNS' },
          { id: 'dns_anomaly', label: 'DNS anomaly/tunneling flag', weight: 24, test: (flow, layers, f, t) => /dns tunneling|dga|dns anomaly/.test(t) },
          { id: 'small_packets', label: 'Small packet pattern', weight: 12, test: (flow, layers, f) => f.bytesPerPacket > 0 && f.bytesPerPacket < 250 },
          { id: 'many_queries', label: 'High query/packet count', weight: 16, test: (flow, layers, f) => f.packets > 30 },
          { id: 'rare_domain', label: 'Rare/new domain context', weight: 14, test: (flow, layers, f, t) => /rare endpoint|new or immature|first seen/.test(t) },
          { id: 'encoded_domain', label: 'Encoded/random-looking domain', weight: 14, test: (flow, layers, f) => /[a-z0-9]{16,}\./i.test(f.domain) }
        ]
      }
    ];
  }

  analyze(flow, layers = {}) {
    const f = normalizeFlow(flow);
    const t = textOf(flow, layers);

    const candidates = this.signatures.map(sig => {
      const checks = sig.checks.map(check => {
        let matched = false;
        try { matched = Boolean(check.test(flow, layers, f, t)); } catch { matched = false; }
        return {
          id: check.id,
          label: check.label,
          matched,
          weight: check.weight
        };
      });

      const totalWeight = checks.reduce((sum, c) => sum + c.weight, 0);
      const matchedWeight = checks.filter(c => c.matched).reduce((sum, c) => sum + c.weight, 0);
      const percent = totalWeight > 0 ? Math.round((matchedWeight / totalWeight) * 100) : 0;
      const matchedCount = checks.filter(c => c.matched).length;

      return {
        family: sig.family,
        description: sig.description,
        percent: clamp(percent, 0, 100),
        matchedCount,
        totalChecks: checks.length,
        checks,
        conclusion: percent >= 75 ? 'STRONG_MATCH' : percent >= 50 ? 'POSSIBLE_MATCH' : percent >= 30 ? 'WEAK_MATCH' : 'NOT_ENOUGH_EVIDENCE'
      };
    }).sort((a, b) => b.percent - a.percent || b.matchedCount - a.matchedCount);

    const top = candidates[0] || null;
    return {
      topFamily: top?.family || 'Unknown',
      topPercent: top?.percent || 0,
      verdict: top?.conclusion || 'NOT_ENOUGH_EVIDENCE',
      candidates
    };
  }
}

module.exports = FamilySignatureEngine;
