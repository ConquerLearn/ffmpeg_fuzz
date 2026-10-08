const fs = require('fs');

// Analyze UAF V2 results - find unique files
const uafData = JSON.parse(fs.readFileSync('.joycode/results-avfree-uaf-v2.sarif', 'utf8'));
const uafResults = uafData.runs[0].results;

// Group by file
const fileCounts = {};
const fileExamples = {};
uafResults.forEach(function(r) {
  var loc = (r.locations || [{}])[0] || {};
  var pl = loc.physicalLocation || {};
  var file = (pl.artifactLocation || {}).uri || '?';
  if (!fileCounts[file]) {
    fileCounts[file] = 0;
    fileExamples[file] = [];
  }
  fileCounts[file]++;
  if (fileExamples[file].length < 3) {
    var line = (pl.region || {}).startLine || '?';
    var msg = (r.message || {}).text || '';
    fileExamples[file].push(file + ':' + line + ' - ' + msg.substring(0, 100));
  }
});

// Sort by count
var sorted = Object.entries(fileCounts).sort(function(a, b) { return b[1] - a[1]; });
console.log('=== AvFreeUseAfterFreeV2: ' + uafResults.length + ' results ===');
console.log('Top 15 files by count:');
sorted.slice(0, 15).forEach(function(e) {
  console.log('  ' + e[1] + 'x ' + e[0]);
  fileExamples[e[0]].forEach(function(ex) { console.log('    ' + ex); });
});

// Analyze AVBufferRef imbalance
const bufData = JSON.parse(fs.readFileSync('.joycode/results-avbuffer-imbalance.sarif', 'utf8'));
const bufResults = bufData.runs[0].results;
const bufFileCounts = {};
const bufFileExamples = {};
bufResults.forEach(function(r) {
  var loc = (r.locations || [{}])[0] || {};
  var pl = loc.physicalLocation || {};
  var file = (pl.artifactLocation || {}).uri || '?';
  if (!bufFileCounts[file]) {
    bufFileCounts[file] = 0;
    bufFileExamples[file] = [];
  }
  bufFileCounts[file]++;
  if (bufFileExamples[file].length < 2) {
    var line = (pl.region || {}).startLine || '?';
    var msg = (r.message || {}).text || '';
    bufFileExamples[file].push(file + ':' + line + ' - ' + msg.substring(0, 100));
  }
});

var bufSorted = Object.entries(bufFileCounts).sort(function(a, b) { return b[1] - a[1]; });
console.log('\n=== AVBufferRefImbalance: ' + bufResults.length + ' results ===');
console.log('Top 15 files by count:');
bufSorted.slice(0, 15).forEach(function(e) {
  console.log('  ' + e[1] + 'x ' + e[0]);
  bufFileExamples[e[0]].forEach(function(ex) { console.log('    ' + ex); });
});

// Analyze Resource Leak V2
const rlData = JSON.parse(fs.readFileSync('.joycode/results-resource-leak-v2.sarif', 'utf8'));
const rlResults = rlData.runs[0].results;
const rlFileCounts = {};
rlResults.forEach(function(r) {
  var loc = (r.locations || [{}])[0] || {};
  var pl = loc.physicalLocation || {};
  var file = (pl.artifactLocation || {}).uri || '?';
  if (!rlFileCounts[file]) rlFileCounts[file] = 0;
  rlFileCounts[file]++;
});
var rlSorted = Object.entries(rlFileCounts).sort(function(a, b) { return b[1] - a[1]; });
console.log('\n=== ResourceLeakErrorPathV2: ' + rlResults.length + ' results ===');
console.log('Top 15 files by count:');
rlSorted.slice(0, 15).forEach(function(e) {
  console.log('  ' + e[1] + 'x ' + e[0]);
});

// Taint tracking summary
console.log('\n=== Taint Tracking Results (Highest Value) ===');
['.joycode/results-tainted-alloc-size.sarif', '.joycode/results-tainted-memcpy-size.sarif', '.joycode/results-tainted-array-index.sarif'].forEach(function(p) {
  var d = JSON.parse(fs.readFileSync(p, 'utf8'));
  var r = d.runs[0].results;
  var rid = (d.runs[0].tool.driver.rules[0] || {}).id || 'unknown';
  console.log('\n' + rid + ': ' + r.length + ' results');
  r.forEach(function(x, i) {
    var loc = (x.locations || [{}])[0] || {};
    var pl = loc.physicalLocation || {};
    var file = (pl.artifactLocation || {}).uri || '?';
    var line = (pl.region || {}).startLine || '?';
    var msg = (x.message || {}).text || '';
    // Also show taint source if available
    var relatedLocs = x.relatedLocations || [];
    var sourceInfo = '';
    if (relatedLocs.length > 0) {
      var srcLoc = relatedLocs[0].physicalLocation || {};
      var srcFile = (srcLoc.artifactLocation || {}).uri || '';
      var srcLine = (srcLoc.region || {}).startLine || '';
      sourceInfo = ' [source: ' + srcFile + ':' + srcLine + ']';
    }
    console.log('  [' + i + '] ' + file + ':' + line + sourceInfo);
    console.log('      ' + msg.substring(0, 150));
  });
});