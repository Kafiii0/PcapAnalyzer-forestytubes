'use strict';

const fs = require('fs').promises;
const path = require('path');
const { normalizeFlow, clamp } = require('./utils');

const DEFAULT_STATE_FILE = path.join(__dirname, '..', 'brain', 'cache', 'entity_reputation.json');

class ReputationEngine {
  constructor(options = {}) {
    this.stateFile = options.stateFile || DEFAULT_STATE_FILE;
    this.state = { version: 1, entities: {} };
  }

  async initialize() {
    await fs.mkdir(path.dirname(this.stateFile), { recursive: true });
    try {
      this.state = JSON.parse(await fs.readFile(this.stateFile, 'utf-8'));
    } catch {
      await this.persist();
    }
  }

  async persist() {
    await fs.writeFile(this.stateFile, JSON.stringify(this.state, null, 2));
  }

  _key(flow) {
    const f = normalizeFlow(flow);
    return f.dstIp || f.domain || 'unknown';
  }

  observe(flow, verdict = {}) {
    const f = normalizeFlow(flow);
    const key = this._key(flow);
    const now = new Date().toISOString();
    const current = this.state.entities[key] || {
      firstSeen: now,
      lastSeen: now,
      sightings: 0,
      detections: 0,
      anomalyCount: 0,
      cleanCount: 0,
      maxScore: 0,
      confidenceTrend: [],
      ports: {},
      domains: {},
      asns: {}
    };

    const score = Number(verdict.score || verdict.confidence || f.heuristicScore || 0);
    current.sightings += 1;
    current.lastSeen = now;
    current.maxScore = Math.max(current.maxScore, score);
    current.ports[f.dstPort] = (current.ports[f.dstPort] || 0) + 1;
    if (f.domain) current.domains[f.domain] = (current.domains[f.domain] || 0) + 1;
    if (f.asnOrg) current.asns[f.asnOrg] = (current.asns[f.asnOrg] || 0) + 1;

    if (score >= 75) current.detections += 1;
    else if (score >= 40) current.anomalyCount += 1;
    else current.cleanCount += 1;

    current.confidenceTrend.push({ ts: now, score: clamp(score) });
    if (current.confidenceTrend.length > 120) current.confidenceTrend = current.confidenceTrend.slice(-120);

    this.state.entities[key] = current;
    return current;
  }

  score(flow) {
    const key = this._key(flow);
    const entity = this.state.entities[key];
    if (!entity) {
      return {
        score: 8,
        flags: ['Reputation: First Seen Entity'],
        violations: [`Entity ${key} baru pertama kali terlihat oleh memory engine.`]
      };
    }

    const flags = [];
    const violations = [];
    let score = 0;

    const badRatio = entity.sightings > 0 ? (entity.detections + entity.anomalyCount * 0.5) / entity.sightings : 0;
    const cleanRatio = entity.sightings > 0 ? entity.cleanCount / entity.sightings : 0;
    const recentScores = entity.confidenceTrend.slice(-8).map(x => x.score);
    const rising = recentScores.length >= 3 && recentScores[recentScores.length - 1] > recentScores[0] + 20;

    if (entity.detections >= 2 || badRatio > 0.55) {
      score += 28;
      flags.push('Reputation: Repeated Suspicious Entity');
      violations.push(`Entity ${key} punya riwayat deteksi/anomali tinggi (${entity.detections} critical, ${entity.anomalyCount} suspicious dari ${entity.sightings} sightings).`);
    }

    if (rising) {
      score += 18;
      flags.push('Reputation: Confidence Trend Rising');
      violations.push(`Confidence trend entity ${key} meningkat dari ${recentScores[0]} ke ${recentScores[recentScores.length - 1]}.`);
    }

    if (cleanRatio > 0.9 && entity.sightings >= 20) {
      score -= 25;
      flags.push('Reputation: Historically Clean');
      violations.push(`Entity ${key} historisnya clean (${entity.cleanCount}/${entity.sightings}); score diturunkan untuk menekan false positive.`);
    }

    return { score: clamp(score, -30, 45), flags, violations, entity };
  }
}

module.exports = ReputationEngine;
