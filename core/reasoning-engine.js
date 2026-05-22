'use strict';

const { normalizeFlow } = require('./utils');

class ReasoningEngine {
  hypothesize(flow, layers = {}) {
    const f = normalizeFlow(flow);
    const flags = [
      ...f.heuristicFlags,
      ...(layers.baseline?.flags || []),
      ...(layers.reputation?.flags || []),
      ...(layers.correlation?.flags || [])
    ];
    const signalText = flags.join(' | ').toLowerCase();

    let hypothesis = 'Traffic appears benign or insufficiently suspicious.';
    let possibleFamilies = ['Clean Traffic'];
    let recommendedAction = 'Monitor dan biarkan engine membangun baseline tambahan.';

    if (/beacon|polling|cadence|low-and-slow|c2/.test(signalText)) {
      hypothesis = 'Likely implant with periodic C2 polling or beaconing behavior.';
      possibleFamilies = ['Cobalt Strike', 'Sliver', 'Havoc', 'Mythic', 'Generic C2 Framework'];
      recommendedAction = 'Isolasi host sumber, blokir endpoint tujuan, lalu validasi proses yang membuka koneksi periodik.';
    }

    if (/exfil|outbound|ftp|smtp|upload/.test(signalText) || f.outboundRatio > 5) {
      hypothesis = 'Likely credential/data exfiltration channel with outbound transfer bias.';
      possibleFamilies = ['Lumma Stealer', 'RedLine', 'AgentTesla', 'PhantomStealer', 'Generic InfoStealer'];
      recommendedAction = 'Blokir koneksi outbound, kumpulkan artefak browser/credential store, dan rotasi kredensial akun terdampak.';
    }

    if (/rat|keepalive|non-standard port|njrat|asyncrat/.test(signalText)) {
      hypothesis = 'Likely RAT/backdoor maintaining an interactive or semi-persistent control channel.';
      possibleFamilies = ['AsyncRAT', 'NjRAT', 'QuasarRAT', 'DCRat', 'Generic RAT'];
      recommendedAction = 'Isolasi host, cari persistence key/service/task, dan lakukan memory/process triage.';
    }

    if (/ioc|ti feed/.test(signalText) && /beacon|exfil|rat|correlated/.test(signalText)) {
      hypothesis = 'Known-threat infrastructure is behaviorally active, not merely a stale IOC match.';
      possibleFamilies = ['Known Malicious Infrastructure', ...possibleFamilies.filter(x => x !== 'Clean Traffic')];
      recommendedAction = 'Treat as confirmed incident: isolate, block IOC, preserve packet evidence, dan mulai incident response.';
    }

    return {
      hypothesis,
      possibleFamilies: [...new Set(possibleFamilies)].slice(0, 6),
      recommendedAction,
      observed: {
        src: f.srcIp,
        dst: f.dstIp,
        port: f.dstPort,
        domain: f.domain,
        flags: [...new Set(flags)].slice(0, 20),
        correlatedSignals: layers.correlation?.signals || []
      }
    };
  }
}

module.exports = ReasoningEngine;
