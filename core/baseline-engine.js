'use strict';

const fs = require('fs').promises;
const path = require('path');
const { mean, stddev, normalizeFlow, shannonEntropy, clamp } = require('./utils');

const DEFAULT_STATE_FILE = path.join(__dirname, '..', 'brain', 'cache', 'adaptive_baseline.json');

class BaselineEngine {
  constructor(options = {}) {
    this.stateFile = options.stateFile || DEFAULT_STATE_FILE;
    this.minSamples = options.minSamples || 8;
    this.state = {
      version: 1,
      updatedAt: null,
      entities: {},
      domains: {},
      asns: {}
    };
  }

  async initialize() {
    await fs.mkdir(path.dirname(this.stateFile), { recursive: true });
    try {
      const raw = await fs.readFile(this.stateFile, 'utf-8');
      this.state = JSON.parse(raw);
    } catch {
      await this.persist();
    }
  }

  async persist() {
    this.state.updatedAt = new Date().toISOString();
    await fs.writeFile(this.stateFile, JSON.stringify(this.state, null, 2));
  }

  _bucketFor(flow) {
    const f = normalizeFlow(flow);
    const domain = f.domain || f.dstIp;
    const asn = f.asnOrg || 'UNKNOWN_ASN';
    return { entity: `${f.dstIp}:${f.dstPort}`, domain, asn };
  }

  _updateBucket(collection, key, sample) {
    if (!key) return;
    const now = new Date().toISOString();
    const entry = collection[key] || {
      firstSeen: now,
      lastSeen: now,
      samples: 0,
      intervals: [],
      bytes: [],
      packets: [],
      durations: [],
      hours: {},
      ports: {},
      entropy: []
    };

    entry.samples += 1;
    entry.lastSeen = now;
    entry.intervals.push(sample.interval);
    entry.bytes.push(sample.bytes);
    entry.packets.push(sample.packets);
    entry.durations.push(sample.duration);
    entry.entropy.push(sample.entropy);
    entry.hours[sample.hour] = (entry.hours[sample.hour] || 0) + 1;
    entry.ports[sample.port] = (entry.ports[sample.port] || 0) + 1;

    for (const field of ['intervals', 'bytes', 'packets', 'durations', 'entropy']) {
      if (entry[field].length > 250) entry[field] = entry[field].slice(-250);
    }

    collection[key] = entry;
  }

  learn(flows = []) {
    for (const flow of flows) {
      const f = normalizeFlow(flow);
      const buckets = this._bucketFor(flow);
      const sample = {
        interval: f.interval,
        bytes: f.bytes,
        packets: f.packets,
        duration: f.duration,
        entropy: shannonEntropy(`${f.httpUri}|${f.domain}|${f.bytes}|${f.packets}`),
        hour: new Date().getHours(),
        port: f.dstPort
      };

      this._updateBucket(this.state.entities, buckets.entity, sample);
      this._updateBucket(this.state.domains, buckets.domain, sample);
      this._updateBucket(this.state.asns, buckets.asn, sample);
    }
  }

  profile(key, type = 'entities') {
    const entry = this.state[type]?.[key];
    if (!entry) return null;
    return {
      ...entry,
      avgInterval: mean(entry.intervals),
      stdInterval: stddev(entry.intervals),
      avgBytes: mean(entry.bytes),
      stdBytes: stddev(entry.bytes),
      avgPackets: mean(entry.packets),
      avgDuration: mean(entry.durations),
      avgEntropy: mean(entry.entropy),
      mature: entry.samples >= this.minSamples
    };
  }

  compare(flow) {
    const f = normalizeFlow(flow);
    const buckets = this._bucketFor(flow);
    const entityProfile = this.profile(buckets.entity, 'entities');
    const domainProfile = this.profile(buckets.domain, 'domains');
    const asnProfile = this.profile(buckets.asn, 'asns');
    const profile = entityProfile || domainProfile || asnProfile;

    if (!profile || !profile.mature) {
      return {
        score: 12,
        flags: ['Baseline: New or Immature Entity'],
        violations: [`Belum ada baseline matang untuk ${buckets.entity}; engine menandai sebagai entity baru sambil belajar.`],
        profileType: entityProfile ? 'entity' : (domainProfile ? 'domain' : (asnProfile ? 'asn' : 'none'))
      };
    }
    

    const flags = [];
    const violations = [];
    let score = 0;

    const intervalDelta = Math.abs(f.interval - profile.avgInterval);
    const bytesDelta = Math.abs(f.bytes - profile.avgBytes);
    const intervalZ = profile.stdInterval > 0 ? intervalDelta / profile.stdInterval : 0;
    const bytesZ = profile.stdBytes > 0 ? bytesDelta / profile.stdBytes : 0;
    const activeHours = Object.keys(profile.hours).map(Number);
    const currentHour = new Date().getHours();
    const seenPort = Boolean(profile.ports[f.dstPort]);

    if (intervalZ >= 3 && f.interval > 0) {
      score += 24;
      flags.push('Baseline Interval Deviation');
      violations.push(`Interval ${f.interval.toFixed(2)}s menyimpang dari baseline ${profile.avgInterval.toFixed(2)}s (z=${intervalZ.toFixed(1)}).`);
    }

    if (bytesZ >= 3 && f.bytes > 0) {
      score += 22;
      flags.push('Baseline Byte Deviation');
      violations.push(`Volume ${f.bytes} bytes menyimpang dari baseline ${profile.avgBytes.toFixed(0)} bytes (z=${bytesZ.toFixed(1)}).`);
    }

    if (!seenPort && f.dstPort > 0) {
      score += 18;
      flags.push('Baseline New Port');
      violations.push(`Port ${f.dstPort} belum pernah muncul pada baseline entity/domain ini.`);
    }

    if (activeHours.length >= 4 && !activeHours.includes(currentHour)) {
      score += 12;
      flags.push('Baseline Active-Hour Drift');
      violations.push(`Aktivitas muncul pada jam ${currentHour}, di luar jam yang biasa terlihat pada baseline.`);
    }

    if (score === 0) {
      flags.push('Baseline Normal');
      violations.push('Traffic masih sesuai baseline historis yang sudah dipelajari.');
    }

    return {
      score: clamp(score, 0, 60),
      flags,
      violations,
      profileType: entityProfile ? 'entity' : (domainProfile ? 'domain' : 'asn'),
      samples: profile.samples
    };
  }
}

module.exports = BaselineEngine;
