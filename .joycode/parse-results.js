const fs = require('fs');
const files = [
  // Original 7 queries
  {path: '.joycode/ffmpeg-memcorr.sarif', name: 'Original Queries'},
  // New 7 queries
  {path: '.joycode/results-avfree-uaf-v2.sarif', name: 'V2 Queries'},
  {path: '.joycode/results-resource-leak-v2.sarif', name: ''},
  {path: '.joycode/results-avpacket-leak.sarif', name: ''},
  {path: '.joycode/results-avbuffer-imbalance.sarif', name: ''},
  {path: '.joycode/results-tainted-alloc-size.sarif', name: ''},
  {path: '.joycode/results-tainted-memcpy-size.sarif', name: ''},
  {path: '.joycode/results-tainted-array-index.sarif', name: ''}
];

console.log('========================================');
console.log('FFmpeg CodeQL Deep Audit - Final Summary');
console.log('========================================\n');

let grandTotal = 0;
const allRules = [];

files.forEach(function(f) {
  try {
    const d = JSON.parse(fs.readFileSync(f.path, 'utf8'));
    const r = d.runs[0].results;
    const rules = d.runs[0].tool.driver.rules;
    rules.forEach(function(rule, idx) {
      const count = r.filter(function(x) { return x.ruleIndex === idx; }).length;
      allRules.push({
        id: rule.id,
        name: rule.name || rule.id,
        severity: (rule.properties || {})['security-severity'] || 'N/A',
        count: count
      });
      grandTotal += count;
    });
  } catch(e) {
    console.log(f.path + ': ERROR - ' + e.message);
  }
});

// Sort by severity (high to low), then by count (high to low)
allRules.sort(function(a, b) {
  const sa = parseFloat(a.severity) || 0;
  const sb = parseFloat(b.severity) || 0;
  if (sb !== sa) return sb - sa;
  return b.count - a.count;
});

console.log('Rule ID'.padEnd(45) + 'Severity'.padEnd(10) + 'Count');
console.log('-'.repeat(65));
allRules.forEach(function(r) {
  console.log(r.id.padEnd(45) + (r.severity + '').padEnd(10) + r.count);
});
console.log('-'.repeat(65));
console.log('TOTAL'.padEnd(45) + ''.padEnd(10) + grandTotal);

console.log('\n========================================');
console.log('HIGH PRIORITY FINDINGS (Taint Tracking)');
console.log('========================================\n');

// Show taint tracking details
['.joycode/results-tainted-alloc-size.sarif', '.joycode/results-tainted-memcpy-size.sarif', '.joycode/results-tainted-array-index.sarif'].forEach(function(p) {
  try {
    const d = JSON.parse(fs.readFileSync(p, 'utf8'));
    const r = d.runs[0].results;
    const rid = (d.runs[0].tool.driver.rules[0] || {}).id || 'unknown';
    console.log(rid + ': ' + r.length + ' results');
    r.forEach(function(x, i) {
      var loc = (x.locations || [{}])[0] || {};
      var pl = loc.physicalLocation || {};
      var file = (pl.artifactLocation || {}).uri || '?';
      var line = (pl.region || {}).startLine || '?';
      var msg = (x.message || {}).text || '';
      var relatedLocs = x.relatedLocations || [];
      var sourceInfo = '';
      if (relatedLocs.length > 0) {
        var srcLoc = relatedLocs[0].physicalLocation || {};
        var srcFile = (srcLoc.artifactLocation || {}).uri || '';
        var srcLine = (srcLoc.region || {}).startLine || '';
        sourceInfo = ' [from: ' + srcFile + ':' + srcLine + ']';
      }
      console.log('  [' + i + '] ' + file + ':' + line + sourceInfo);
    });
    console.log('');
  } catch(e) {}
});

console.log('========================================');
console.log('UAF V2 vs V1 Comparison');
console.log('========================================\n');

// Load V1 data
try {
  const v1Data = JSON.parse(fs.readFileSync('.joycode/ffmpeg-memcorr.sarif', 'utf8'));
  const v1UAF = v1Data.runs[0].results.filter(function(x) {
    return (v1Data.runs[0].tool.driver.rules[x.ruleIndex] || {}).id === 'cpp/ffmpeg-av-free-use-after-free';
  }).length;

  const v2Data = JSON.parse(fs.readFileSync('.joycode/results-avfree-uaf-v2.sarif', 'utf8'));
  const v2UAF = v2Data.runs[0].results.length;

  console.log('AvFreeUseAfterFree V1: ' + v1UAF + ' results');
  console.log('AvFreeUseAfterFree V2: ' + v2UAF + ' results');
  console.log('Reduction: ' + ((1 - v2UAF/v1UAF) * 100).toFixed(1) + '%');
} catch(e) {
  console.log('Error: ' + e.message);
}