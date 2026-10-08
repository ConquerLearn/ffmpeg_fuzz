const fs = require('fs');
const s = JSON.parse(fs.readFileSync(process.argv[2] || 'codeql-ffmpeg-full.sarif', 'utf8'));
const runs = s.runs[0];
const results = runs.results;
console.log('total results:', results.length);

const byRule = {};
const bySev = {};
const byKind = {};
const byLoc = {};
for (const r of results) {
  const k = r.ruleId || '?';
  byRule[k] = (byRule[k] || 0) + 1;
  const p = (r.properties && (r.properties['security-severity'] || r.properties.securitySeverity)) || 'none';
  bySev[p] = (bySev[p] || 0) + 1;
  const kd = r.kind || '?';
  byKind[kd] = (byKind[kd] || 0) + 1;
  if (r.locations && r.locations[0] && r.locations[0].physicalLocation && r.locations[0].physicalLocation.artifactLocation) {
    const f = r.locations[0].physicalLocation.artifactLocation.uri;
    byLoc[f] = (byLoc[f] || 0) + 1;
  }
}
console.log('by severity:', JSON.stringify(bySev));
console.log('by kind:', JSON.stringify(byKind));
console.log('--- top rules ---');
for (const [k, v] of Object.entries(byRule).sort((a, b) => b[1] - a[1]).slice(0, 50)) console.log(v, k);
console.log('--- top files ---');
for (const [k, v] of Object.entries(byLoc).sort((a, b) => b[1] - a[1]).slice(0, 30)) console.log(v, k);
