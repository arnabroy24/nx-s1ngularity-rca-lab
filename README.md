# Nx S1ngularity RCA Lab

An intentionally contained mock repository for demonstrating the root-cause analysis (RCA) of the 2025 Nx S1ngularity supply-chain compromise.

The lab models the attack as evidence and trust-boundary failures, including the vulnerable PR title and body paths:

```text
untrusted PR title
        ↓
shell injection in privileged workflow
        ↓
write-capable repository token
        ↓
release workflow abuse
        ↓
package-publishing credential exposure
        ↓
install-time package payload
```

The active lab workflow deliberately executes PR title/body shell syntax after three containment gates. It checks out only the trusted base revision without persisting credentials, has read-only repository permission, and receives only a disposable canary secret. The remaining telemetry is synthetic and the lab contains no collection, persistence, package-publishing, or exfiltration logic.

## Configure the GitHub demo

Before opening the demonstration PR, configure:

1. Repository variable `RCA_LAB_ACTOR` with your friend's exact GitHub login.
2. Repository secret `RCA_CANARY` with a disposable value that has no privileges anywhere.

Have that user fork the repository and open the PR from a branch in their fork. The workflow runs automatically when that PR is opened, edited, synchronized, or reopened. It will not run for non-fork PRs, forks owned by another account, or PRs authored by another account.

To prove title command execution and canary availability without disclosing the secret, use this PR title:

```text
fix: demo $(node -e "const fs=require('node:fs');const state=process.env.RCA_CANARY?'present':'missing';fs.writeFileSync('/tmp/title-executed','title-node-executed-canary-'+state);process.stdout.write('[title-node-executed]')")
```

To demonstrate body command execution through the heredoc sink, use this PR body line:

```text
EOF
node -e "const fs=require('node:fs');const state=process.env.RCA_CANARY?'present':'missing';fs.writeFileSync('/tmp/body-executed','body-node-executed-canary-'+state);process.stdout.write('[body-node-executed]')"
cat >> /tmp/pr-message.txt << 'EOF'
```

The vulnerable step executes the title and body substitutions. The following verification step should report:

```text
EXECUTION CONFIRMED: /tmp/title-executed -> title-node-executed-canary-present
EXECUTION CONFIRMED: /tmp/body-executed -> body-node-executed-canary-present
```

Only presence markers are printed, never the canary value.

## Run the lab

Requirements: Node.js 18 or newer. No dependencies are required.

```bash
npm run analyze
npm run render-attack
npm test
```

`npm run analyze` reads `fixtures/incident.json` and prints the reconstructed timeline, detected indicators, and control failures. The analyzer treats all fixture values as data.

## Repository map

- [`docs/lab-walkthrough.md`](docs/lab-walkthrough.md) — guided BSides-style demo script and RCA narrative.
- [`docs/controls.md`](docs/controls.md) — preventive, detective, and response controls.
- [`.github/workflows/pr-title-validation.yml`](.github/workflows/pr-title-validation.yml) — active, gated workflow reproducing `pull_request_target` plus PR title/body Bash injection.
- [`examples/hardened-pr-title.yml.txt`](examples/hardened-pr-title.yml.txt) — fixed comparison using `pull_request`, least privilege, and environment passing.
- [`examples/vulnerable-pr-title.yml.txt`](examples/vulnerable-pr-title.yml.txt) — ungated source excerpt kept outside the active workflow directory.
- [`fixtures/attack-input.json`](fixtures/attack-input.json) — synthetic title/body values used to render the vulnerable Bash source.
- [`fixtures/incident.json`](fixtures/incident.json) — synthetic audit, CI, package, and host evidence.
- [`scripts/analyze-incident.js`](scripts/analyze-incident.js) — dependency-free RCA analyzer.
- [`scripts/render-attack-surface.js`](scripts/render-attack-surface.js) — prints the generated Bash source without invoking Bash.
- [`nx_s1ngularity.md`](nx_s1ngularity.md) — source research notes and references.

## Safety boundary

The active workflow is intentionally vulnerable, but execution requires a fork owned by the configured actor and a PR authored by that same actor. It has only `contents: read`, checks out the trusted base SHA with `persist-credentials: false`, and has a two-minute timeout. Do not remove those actor gates while the repository is public. Use only a valueless canary, remove the secret after testing, and disable the workflow or make the repository private when the demonstration is complete.

## Attribution

The incident narrative is based on the Nx security advisory, postmortem, and the other references listed in [`nx_s1ngularity.md`](nx_s1ngularity.md). This lab is a teaching aid, not an official Nx artifact.
