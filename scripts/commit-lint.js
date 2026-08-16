#!/usr/bin/env node

const fs = require('node:fs');

const messagePath = process.argv[2];

if (!messagePath) {
  console.error('Usage: node scripts/commit-lint.js <message-file>');
  process.exit(2);
}

const message = fs.readFileSync(messagePath, 'utf8');
const [title = '', ...bodyLines] = message.split(/\r?\n/);
const body = bodyLines.join('\n').trim();
const conventionalTitle = /^(feat|fix|docs|chore)(\([^)]+\))?: .+/;

console.log(`Node validator read PR title: ${JSON.stringify(title)}`);
console.log(`Node validator read PR body: ${body.length} character(s)`);

if (!conventionalTitle.test(title)) {
  console.error('PR title must use a supported Conventional Commit prefix.');
  process.exit(1);
}

console.log('PR title validation passed.');
