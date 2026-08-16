# Lab walkthrough

This is a 10-minute demonstration for a security talk or tabletop exercise. The active GitHub workflow is intentionally vulnerable but gated to a fork owned by the configured demo actor, a PR authored by that same actor, and a maintainer-applied label.

## 1. Establish the root cause

Open [`.github/workflows/pr-title-validation.yml`](../.github/workflows/pr-title-validation.yml). Ask the audience what controls the values inside the `echo` and heredoc. The answer is the pull-request author. GitHub expression substitution happens before Bash receives the generated script, so shell syntax in the title or body becomes part of the generated command stream.

Then point out `pull_request_target`. The workflow receives the base repository security context even though the task only validates metadata. The vulnerability is therefore crossing two boundaries at once: data-to-code and untrusted-event-to-privileged-runner.

Before the live run, set repository variable `RCA_LAB_ACTOR` to the friend's exact GitHub login, set repository secret `RCA_CANARY`, and create the `rca-lab-approved` label. The friend must open the PR from a fork they own. The label is the final maintainer-controlled execution gate.

Use the title and body probes from the README. The title's command substitution launches Node from inside the vulnerable `echo`. The body closes the quoted heredoc, launches Node as a new generated-shell command, and opens a replacement heredoc for the workflow's original closing delimiter. Each Node process records only canary presence in a distinct file under `/tmp`. The workflow then runs `node ./scripts/commit-lint.js /tmp/pr-message.txt`, matching the RCA sequence, and a final step verifies both execution markers.

For an offline preview, `npm run render-attack` substitutes synthetic title/body values into the source without starting Bash.

## 2. Follow the privilege pivot

Run:

```bash
npm run analyze
```

The synthetic timeline shows the resulting chain without performing it:

1. A title-validation job executes in a privileged context.
2. Repository write access is used to create content and dispatch a publish workflow.
3. The publish runner attempts to send an npm credential outside the pipeline.
4. A malicious package version appears in the registry feed.
5. Installation reaches a lifecycle script and produces host indicators.

The analyzer only compares strings and prints fixture data. It never interprets the `detail` fields as commands.

## 3. Connect package behavior to detection

The package fixture models an affected version with an install-time script. The host indicators show why package compromise is not limited to the top-level dependency declaration: lockfiles, caches, editor extensions, transitive installs, and `node_modules` all matter.

Use the indicators to ask what each telemetry source can prove:

| Evidence | What it supports | What it does not prove alone |
| --- | --- | --- |
| `workflow.job_command_execution` | privileged CI execution of attacker-controlled input | that npm was published by the same actor |
| `workflow.dispatch` | a release-workflow pivot | that the release job exposed a secret |
| `secret.egress_attempt` | attempted credential boundary crossing | successful credential theft |
| `package.publish` | package distribution | that every consumer installed it |
| host indicators | install-time impact on a developer machine | the full scope of exposed credentials |

## 4. Show the control diff

Compare the active vulnerable workflow with [`examples/hardened-pr-title.yml.txt`](../examples/hardened-pr-title.yml.txt):

- `pull_request` is sufficient for metadata validation.
- `contents: read` makes the permission explicit.
- `PR_TITLE` and `PR_BODY` are passed as environment values and quoted as data.
- The fixed example is stored as `.txt` so it does not create a second active check during the demo.

Finish with [`docs/controls.md`](controls.md) and ask the audience which controls are preventive, detective, and response-oriented.
