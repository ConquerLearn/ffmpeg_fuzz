const fs = require('fs');
const path = require('path');

const sarifPath = process.argv[2] || '.joycode/results-custom-queries.sarif';
const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));

for (const run of sarif.runs) {
  console.log(`\n=== Query Pack: ${run.tool.driver.name} ===`);
  
  // Build rule lookup
  const rules = {};
  for (const rule of run.tool.driver.rules || []) {
    rules[rule.id] = rule;
  }
  
  // Group results by rule
  const byRule = {};
  for (const result of run.results || []) {
    const ruleId = result.ruleId;
    if (!byRule[ruleId]) byRule[ruleId] = [];
    byRule[ruleId].push(result);
  }
  
  for (const [ruleId, results] of Object.entries(byRule)) {
    const rule = rules[ruleId] || {};
    const severity = rule.properties?.['security-severity'] || rule.properties?.['problem.severity'] || 'unknown';
    console.log(`\n--- ${ruleId} (${results.length} findings, severity: ${severity}) ---`);
    console.log(`    ${rule.shortDescription?.text || rule.fullDescription?.text || 'No description'}`);
    
    // Show top 15 results with file:line
    let shown = 0;
    for (const r of results) {
      if (shown >= 15) {
        console.log(`    ... and ${results.length - 15} more`);
        break;
      }
      const loc = r.locations?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri ? path.basename(loc.artifactLocation.uri) : 'unknown';
      const line = loc?.region?.startLine || '?';
      const msg = r.message?.text || '';
      // Truncate message
      const shortMsg = msg.length > 120 ? msg.substring(0, 120) + '...' : msg;
      console.log(`    ${file}:${line} - ${shortMsg}`);
      shown++;
    }
  }
  
  console.log(`\nTotal results: ${run.results?.length || 0}`);
}