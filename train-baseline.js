'use strict';


const fs = require('fs').promises;
const path = require('path');
const adaptiveEngine = require('./core/adaptive-engine');

async function main() {
  const inputFile = process.argv[2] || 'output.json';
  const fullPath = path.resolve(process.cwd(), inputFile);

  let raw;
  try {
    raw = await fs.readFile(fullPath, 'utf-8');
  } catch (err) {
    console.error(`[train] Gagal membaca file: ${fullPath}`);
    console.error(`[train] ${err.message}`);
    process.exit(1);
  }

  let flows;
  try {
    flows = JSON.parse(raw);
  } catch (err) {
    console.error('[train] Format JSON tidak valid. Pastikan input adalah output.json dari extractor.');
    console.error(`[train] ${err.message}`);
    process.exit(1);
  }

  if (!Array.isArray(flows) || flows.length === 0) {
    console.error('[train] File JSON harus berisi array flow dan tidak boleh kosong.');
    process.exit(1);
  }

  await adaptiveEngine.initialize();
  const analyzed = await adaptiveEngine.analyze(flows);

  const levels = analyzed.reduce((acc, flow) => {
    const level = flow.adaptive?.level || 'UNKNOWN';
    acc[level] = (acc[level] || 0) + 1;
    return acc;
  }, {});

  console.log('[train] Local adaptive learning selesai.');
  console.log(`[train] File        : ${fullPath}`);
  console.log(`[train] Total flow  : ${flows.length}`);
  console.log(`[train] Level count : ${JSON.stringify(levels)}`);
  console.log('[train] Memory tersimpan di:');
  console.log('        brain/cache/adaptive_baseline.json');
  console.log('        brain/cache/entity_reputation.json');
}

main().catch(err => {
  console.error('[train] Fatal error:', err);
  process.exit(1);
});
