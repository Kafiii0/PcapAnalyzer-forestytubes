'use strict';

const BaselineEngine = require('./baseline-engine');
const ReputationEngine = require('./reputation-engine');
const CorrelationEngine = require('./correlation-engine');
const ScoringEngine = require('./scoring-engine');
const ReasoningEngine = require('./reasoning-engine');
const FamilySignatureEngine = require('./family-signature-engine');

class AdaptiveEngine {
  constructor(options = {}) {
    this.baseline = new BaselineEngine(options.baseline || {});
    this.reputation = new ReputationEngine(options.reputation || {});
    this.correlation = new CorrelationEngine();
    this.scoring = new ScoringEngine();
    this.reasoning = new ReasoningEngine();
    this.familySignature = new FamilySignatureEngine();
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) return;
    await this.baseline.initialize();
    await this.reputation.initialize();
    this.initialized = true;
  }

  async analyze(flows = []) {
    await this.initialize();

    const analyzed = flows.map(flow => {
      const baseline = this.baseline.compare(flow);
      const reputation = this.reputation.score(flow);
      const correlation = this.correlation.analyze(flow, { baseline, reputation });
      const scoring = this.scoring.calculate(flow, { baseline, reputation, correlation });
      const reasoning = this.reasoning.hypothesize(flow, { baseline, reputation, correlation, scoring });
      const familyMatrix = this.familySignature.analyze(flow, { baseline, reputation, correlation, scoring, reasoning });

      const adaptive = {
        score: scoring.finalScore,
        level: scoring.level,
        flags: [
          ...(baseline.flags || []),
          ...(reputation.flags || []),
          ...(correlation.flags || []),
          familyMatrix.topPercent >= 50 ? `Family Match: ${familyMatrix.topFamily} (${familyMatrix.topPercent}%)` : null
        ].filter(Boolean),
        violations: [
          ...(baseline.violations || []),
          ...(reputation.violations || []),
          ...(correlation.violations || []),
          familyMatrix.topPercent >= 50 ? `Family Signature Matrix: ${familyMatrix.topFamily} memenuhi ${familyMatrix.topPercent}% indikator signature.` : null
        ].filter(Boolean),
        baseline,
        reputation: {
          score: reputation.score,
          flags: reputation.flags,
          violations: reputation.violations
        },
        correlation,
        scoring,
        reasoning,
        family_matrix: familyMatrix
      };

      this.reputation.observe(flow, adaptive);
      return { ...flow, adaptive };
    });

    this.baseline.learn(flows);
    await this.baseline.persist();
    await this.reputation.persist();

    return analyzed;
  }
}

module.exports = new AdaptiveEngine();
module.exports.AdaptiveEngine = AdaptiveEngine;
