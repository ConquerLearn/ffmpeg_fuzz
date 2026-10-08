const fs = require('fs');
const s = JSON.parse(fs.readFileSync('.joycode/ffmpeg-memcorr.sarif', 'utf8'));
const runs = s.runs[0];
const results = runs.results;
const rules = {};
for (const r of runs.tool.driver.rules) rules[r.id] = r;

// Only the top 4 most critical rules - concise output
for (const ruleId of ['cpp/overflow-buffer', 'cpp/uncontrolled-allocation-size', 'cpp/improper-null-termination', 'cpp/integer-overflow-tainted']) {
  const matches = results.filter(r => r.ruleId === ruleId);
  if (matches.length === 0) { console.log(`\n=== ${ruleId}: NO FINDINGS ===`); continue; }
  const ri = rules[ruleId] || {};
  const sev = ri.properties && ri.properties['security-severity'] || 'N/A';
  console.log(`\n=== ${ruleId} (${matches.length} findings, sev=${sev}) ===`);
  console.log(`  ${(ri.shortDescription || {}).text || ''}`);
  for (const m of matches) {
    const loc = m.locations && m.locations[0] && m.locations[0].physicalLocation;
    const file = loc ? loc.artifactLocation.uri : '?';
    const line = loc && loc.region ? loc.region.startLine : '?';
    const msg = m.message && m.message.text ? m.message.text.substring(0, 200) : '';
    console.log(`  [${file}:${line}] ${msg}`);
  }
}

// tainted-arithmetic - just count by file
const ta = results.filter(r => r.ruleId === 'cpp/tainted-arithmetic');
console.log(`\n=== cpp/tainted-arithmetic (${ta.length} findings) ===`);
const byFile = {};
for (const m of ta) {
  const loc = m.locations && m.locations[0] && m.locations[0].physicalLocation;
  const file = loc ? loc.artifactLocation.uri : '?';
  byFile[file] = (byFile[file] || 0) + 1;
}
for (const [k,v] of Object.entries(byFile).sort((a,b) => b[1]-a[1])) console.log(`  ${v} ${k}`);

// integer-overflow-tainted by file
const iot = results.filter(r => r.ruleId === 'cpp/integer-overflow-tainted');
console.log(`\n=== cpp/integer-overflow-tainted (${iot.length} findings) ===`);
const byFile2 = {};
for (const m of iot) {
  const loc = m.locations && m.locations[0] && m.locations[0].physicalLocation;
  const file = loc ? loc.artifactLocation.uri : '?';
  const line = loc && loc.region ? loc.region.startLine : '?';
  byFile2[file] = (byFile2[file] || 0) + 1;
}
for (const [k,v] of Object.entries(byFile2).sort((a,b) => b[1]-a[1])) console.log(`  ${v} ${k}`);