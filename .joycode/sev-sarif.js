const fs = require('fs');
const s = JSON.parse(fs.readFileSync(process.argv[2] || '.joycode/ffmpeg-memcorr.sarif', 'utf8'));
const runs = s.runs[0];
const results = runs.results;
const rules = {};
for (const r of runs.tool.driver.rules) rules[r.id] = r;

// Only the most critical: overflow-buffer, uncontrolled-alloc, null-termination, integer-overflow-tainted, tainted-arithmetic
const criticalRules = [
  'cpp/overflow-buffer', 'cpp/uncontrolled-allocation-size', 'cpp/improper-null-termination',
  'cpp/integer-overflow-tainted', 'cpp/tainted-arithmetic'
];

for (const ruleId of criticalRules) {
  const matches = results.filter(r => r.ruleId === ruleId);
  if (matches.length === 0) continue;
  const ruleInfo = rules[ruleId] || {};
  const sev = ruleInfo.properties && ruleInfo.properties['security-severity'] || 'N/A';
  const cwe = ruleInfo.properties && ruleInfo.properties['cwe'] || 'N/A';
  console.log(`\n=== ${ruleId} (${matches.length} findings, severity=${sev}, cwe=${JSON.stringify(cwe)}) ===`);
  console.log(`  Desc: ${(ruleInfo.shortDescription || {}).text || 'N/A'}`);
  
  for (const m of matches) {
    const loc = m.locations && m.locations[0] && m.locations[0].physicalLocation;
    const file = loc ? loc.artifactLocation.uri : '?';
    const line = loc && loc.region ? loc.region.startLine : '?';
    const msg = m.message && m.message.text ? m.message.text.substring(0, 250) : '';
    console.log(`  [${file}:${line}] ${msg}`);
    if (m.relatedLocations) {
      for (const rl of m.relatedLocations.slice(0, 5)) {
        const rlLoc = rl.physicalLocation;
        if (rlLoc) {
          const rf = rlLoc.artifactLocation.uri;
          const rl2 = rlLoc.region ? rlLoc.region.startLine : '?';
          const rm = rl.message ? rl.message.text.substring(0, 120) : '';
          console.log(`    -> [${rf}:${rl2}] ${rm}`);
        }
      }
    }
  }
}