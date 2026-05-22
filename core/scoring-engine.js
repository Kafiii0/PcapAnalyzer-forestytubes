'use strict';

const { clamp, normalizeFlow } = require('./utils');

class ScoringEngine {
  calculate(flow, layers = {}) {
    const f = normalizeFlow(flow);
    const baseScore = clamp(f.heuristicScore || 15);
    const baselineScore = layers.baseline?.score || 0;
    const reputationScore = layers.reputation?.score || 0;
    const correlationScore = layers.correlation?.score || 0;

    const rarityMultiplier = layers.baseline?.flags?.includes('Baseline: New or Immature Entity') ? 1.10 : 1.0;
    const temporalMultiplier = layers.baseline?.flags?.includes('Baseline Active-Hour Drift') ? 1.08 : 1.0;
    const entropyMultiplier = f.heuristicFlags.some(x => /entropy|obfuscated|encrypted/i.test(x)) ? 1.10 : 1.0;
    const correlationMultiplier = correlationScore >= 45 ? 1.18 : (correlationScore >= 25 ? 1.10 : 1.0);
    const trustDiscount = f.autoTrusted ? 35 : 0;

    const weighted = (
      baseScore * 0.55 +
      baselineScore * 0.18 +
      Math.max(0, reputationScore) * 0.12 +
      correlationScore * 0.35
    );

    const finalScore = clamp(
      weighted * rarityMultiplier * temporalMultiplier * entropyMultiplier * correlationMultiplier - trustDiscount
    );

    let level = 'SAFE';
    if (finalScore >= 75) level = 'CRITICAL';
    else if (finalScore >= 40) level = 'SUSPICIOUS';

    return {
      baseScore,
      finalScore: Math.round(finalScore),
      level,
      multipliers: {
        rarityMultiplier,
        temporalMultiplier,
        entropyMultiplier,
        correlationMultiplier,
        trustDiscount
      }
    };
  }
}

module.exports = ScoringEngine;
