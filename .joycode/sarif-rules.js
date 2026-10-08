const fs = require('fs');
const s = JSON.parse(fs.readFileSync('.joycode/ffmpeg-memcorr.sarif', 'utf8'));
const runs = s.runs[0];
const rules = runs.tool.driver.rules || [];
console.log('rules in SARIF:', rules.length);
for (const r of rules) {
  const sev = r.properties && r.properties['security-severity'];
  console.log(r.id, 'sev=' + (sev || '-'), 'level=' + (r.defaultConfiguration && r.defaultConfiguration.level));
}
// check invocations / notifications for errors
if (runs.invocations) {
  for (const inv of runs.invocations) {
    if (inv.toolExecutionNotifications) {
      for (const n of inv.toolExecutionNotifications) console.log('NOTIF:', n.level, n.message && n.message.text);
    }
  }
}
