#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const workflowPath = path.join(__dirname, '..', 'examples', 'vulnerable-pr-title.yml.txt');
const inputPath = path.join(__dirname, '..', 'fixtures', 'attack-input.json');
const workflow = fs.readFileSync(workflowPath, 'utf8');
const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));

const rendered = workflow
  .replaceAll('${{ github.event.pull_request.title }}', input.title)
  .replaceAll('${{ github.event.pull_request.body }}', input.body);

console.log('Synthetic GitHub expression substitution preview');
console.log('The rendered workflow is printed as text only; no shell is started.');
console.log('');
console.log(rendered);
