const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { detectedFindings, incident } = require('./analyze-incident');

const findings = detectedFindings(incident.events).map((finding) => finding.name);

assert.deepEqual(findings, incident.expectedFindings);
assert.equal(incident.package.name, 'nx');
assert.equal(incident.package.version, '21.5.0');
assert.equal(incident.attackSurface.event, 'pull_request_target');
assert.deepEqual(incident.attackSurface.interpolatedFields, [
  'github.event.pull_request.title',
  'github.event.pull_request.body'
]);
assert.ok(incident.metadata.source.includes('Synthetic'));
assert.ok(incident.events.length >= 5);

const workflow = fs.readFileSync(
  path.join(__dirname, '..', '.github', 'workflows', 'pr-title-validation.yml'),
  'utf8'
);

for (const requiredPattern of [
  'pull_request_target:',
  '${{ github.event.pull_request.title }}',
  '${{ github.event.pull_request.body }}',
  '${{ secrets.RCA_CANARY }}',
  'github.event.pull_request.head.repo.fork == true',
  'github.event.pull_request.head.repo.owner.login == vars.RCA_LAB_ACTOR',
  'github.event.pull_request.user.login == vars.RCA_LAB_ACTOR',
  'contents: read',
  'persist-credentials: false',
  "cat > /tmp/pr-message.txt << 'EOF'",
  'node ./scripts/commit-lint.js /tmp/pr-message.txt',
  'timeout-minutes: 2',
  '/tmp/title-executed',
  '/tmp/body-executed',
  'EXECUTION CONFIRMED:'
]) {
  assert.ok(workflow.includes(requiredPattern), `workflow is missing: ${requiredPattern}`);
}

assert.ok(!workflow.includes('rca-lab-approved'), 'workflow must not depend on an approval label');

assert.ok(
  workflow.indexOf("cat > /tmp/pr-message.txt << 'EOF'") <
    workflow.indexOf('echo "Validating PR title:'),
  'workflow must construct the message before the vulnerable title echo'
);

console.log(`PASS: detected ${findings.length} RCA findings and verified the gated vulnerable workflow.`);
