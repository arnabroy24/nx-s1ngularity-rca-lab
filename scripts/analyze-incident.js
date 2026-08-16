#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const fixturePath = path.join(__dirname, '..', 'fixtures', 'incident.json');
const incident = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

const findingRules = [
  {
    name: 'PR title/body script injection',
    evidence: ['workflow.job_command_execution'],
    control: 'Pass untrusted metadata through env/action inputs; never interpolate it into run:.'
  },
  {
    name: 'privileged pull_request_target',
    evidence: ['workflow.job_command_execution'],
    control: 'Use pull_request for metadata validation and grant explicit read-only permissions.'
  },
  {
    name: 'workflow-to-workflow pivot',
    evidence: ['workflow.dispatch'],
    control: 'Protect dispatchable release workflows with approval, branch constraints, and separate credentials.'
  },
  {
    name: 'npm credential exposure',
    evidence: ['secret.egress_attempt'],
    control: 'Prefer short-lived trusted publishing/OIDC and alert on secret egress.'
  },
  {
    name: 'install-time execution',
    evidence: ['package.publish', 'install_hook.network_attempt'],
    control: 'Review lockfiles, isolate installs, and monitor package lifecycle scripts and egress.'
  }
];

function detectedFindings(events) {
  const actions = new Set(events.map((event) => event.action));
  return findingRules.filter((rule) => rule.evidence.some((action) => actions.has(action)));
}

function printReport(data) {
  const findings = detectedFindings(data.events);
  console.log(`\n${data.metadata.caseId}`);
  console.log(data.metadata.source);
  console.log('\nReconstructed timeline');
  for (const event of data.events) {
    console.log(`${event.time} | ${event.source.padEnd(16)} | ${event.action.padEnd(30)} | ${event.detail}`);
  }

  console.log('\nRCA findings');
  for (const finding of findings) {
    console.log(`- ${finding.name}: ${finding.control}`);
  }

  console.log('\nPackage fixture');
  console.log(`- ${data.package.name}@${data.package.version} (${data.package.status})`);
  console.log(`- lifecycle behavior is represented as text only: ${data.package.installScript}`);

  console.log('\nHost indicators');
  for (const indicator of data.hostIndicators) console.log(`- ${indicator}`);

  console.log('\nSafety: no network requests, shell commands, package installs, or fixture-driven code execution occurred.');
  return findings;
}

if (require.main === module) printReport(incident);

module.exports = { detectedFindings, findingRules, incident };
