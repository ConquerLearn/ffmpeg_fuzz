const fs = require('fs');
const s = JSON.parse(fs.readFileSync(process.argv[2] || '.joycode/ffmpeg-memcorr.sarif', 'utf8'));
const runs = s.runs[0];
const results = runs.results;
const rules = {};
for (const r of runs.tool.driver.rules) rules[r.id] = r;

// Focus on security-critical rules
const criticalRules = [
  'cpp/overflow-buffer', 'cpp/uncontrolled-allocation-size', 'cpp/improper-null-termination',
  'cpp/integer-overflow-tainted', 'cpp/tainted-arithmetic', 'cpp/suspicious-add-sizeof',
  'cpp/suspicious-call-to-memset', 'cpp/stack-address-escape', 'cpp/conditionally-uninitialized-variable',
  'cpp/incorrect-pointer-scaling-char', 'cpp/missing-null-test', 'cpp/inconsistent-nullness-testing',
  'cpp/suspicious-pointer-scaling', 'cpp/uninitialized-local'
];

for (const ruleId of criticalRules) {
  const matches = results.filter(r => r.ruleId === ruleId);
  if (matches.length === 0) continue;
  const ruleInfo = rules[ruleId] || {};
  const sev = ruleInfo.properties && ruleInfo.properties['security-severity'] || 'N/A';
  const cwe = ruleInfo.properties && ruleInfo.properties['cwe'] || 'N/A';
  console.log(`\n=== ${ruleId} (${matches.length} findings, severity=${sev}, cwe=${cwe}) ===`);
  console.log(`  Message: ${(ruleInfo.shortDescription || {}).text || 'N/A'}`);
  
  for (const m of matches.slice(0, 15)) {
    const loc = m.locations && m.locations[0] && m.locations[0].physicalLocation;
    const file = loc ? loc.artifactLocation.uri : '?';
    const line = loc && loc.region ? loc.region.startLine : '?';
    const msg = m.message && m.message.text ? m.message.text.substring(0, 120) : '';
    console.log(`  [${file}:${line}] ${msg}`);
  }
  if (matches.length > 15) console.log(`  ... and ${matches.length - 15} more`);
}