# Controls mapped to the RCA

## Preventive

- Keep PR titles, bodies, branch names, labels, and comments out of generated shell source. Use environment variables or action inputs, then quote variables in the shell.
- Use `pull_request` for untrusted contribution validation. Reserve `pull_request_target` for narrow metadata-only tasks that genuinely need it.
- Set workflow permissions explicitly. A title linter needs `contents: read`, not repository write access.
- Protect `workflow_dispatch` release paths with environment approval, trusted branches, and code ownership.
- Use npm trusted publishing/OIDC or another short-lived credential model instead of a long-lived publishing token.
- Treat package lifecycle hooks as code execution; isolate installs and pin dependencies through reviewed lockfiles.

## Detective

- Alert on repository creation, visibility changes, workflow dispatch, and workflow deletion by CI identities.
- Monitor CI egress and block unexpected destinations, especially from release jobs.
- Alert when `gh`, npm, or cloud credential tooling is invoked from an install process.
- Scan lockfiles, caches, `node_modules`, and editor extension package trees for affected versions.
- Monitor shell startup files and temporary inventory paths for unexpected changes.

## Response

- Isolate an affected host and preserve CI, GitHub audit, npm, shell, and endpoint telemetry.
- Remove the affected package using a known-good lockfile and reinstall in a clean environment.
- Rotate every credential available to the affected process: GitHub, npm, SSH, cloud, `.env`, and wallet material.
- Review repository creation, token use, workflow dispatch/deletion, package publication, and public repository activity.
- Remove persistence and temporary artifacts only after preserving evidence.

## RCA framing

The central lesson is not “sanitize one string.” The incident required several failures to compose: untrusted input became shell source, a metadata check ran with a privileged event, repository write access could reach a release workflow, and a long-lived publishing credential was available to that workflow. Defense in depth should break the chain at each boundary.
