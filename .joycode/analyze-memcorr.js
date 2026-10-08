const fs = require('fs');
const s = JSON.parse(fs.readFileSync('.joycode/ffmpeg-memcorr.sarif', 'utf8'));
const runs = s.runs[0];
const results = runs.results || [];
console.log('total results:', results.length);
const rules = new Map((runs.tool.driver.rules || []).map(r => [r.id, r]));
const byRule = {};
const bySev = {};
for (const r of results) {
  const rule = rules.get(r.ruleId);
  const sev = rule && rule.properties && rule.properties['security-severity'];
  byRule[r.ruleId] = (byRule[r.ruleId] || 0) + 1;
  if (sev) bySev[sev] = (bySev[sev] || 0) + 1;
}
console.log('--- by rule ---');
for (const [k, v] of Object.entries(byRule).sort((a, b) => b[1] - a[1])) {
  const rule = rules.get(k);
  const sev = rule && rule.properties && rule.properties['security-severity'];
  const lvl = rule && rule.defaultConfiguration ? rule.defaultConfiguration.level : '';
  console.log(v, k, 'sev=' + (sev || '-'), 'lvl=' + lvl);
}
// list every result with location, excluding noisy rules
console.log('--- all results detail ---');
const noisy = new Set(['cpp/suspicious-pointer-scaling', 'cpp/suspicious-add-sizeof', 'cpp/integer-multiplication-cast-to-long']);
for (const r of results) {
  if (noisy.has(r.ruleId)) continue;
  const rule = rules.get(r.ruleId);
  const sev = rule && rule.properties && rule.properties['security-severity'];
  const loc = r.locations && r.locations[0] && r.locations[0].physicalLocation;
  const uri = loc ? loc.artifactLocation.uri : '?';
  const region = loc && loc.region ? `${loc.region.startLine}:${loc.region.startColumn}` : '?:?';
  console.log(`[sev=${sev || '-'}] ${r.ruleId} ${uri}:${region} | ${r.message.text.slice(0, 140)}`);
}
