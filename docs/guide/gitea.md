# Gitea (`gitea.com` and self-hosted)

OpsCrew supports repositories hosted on [Gitea](https://about.gitea.com/) — both `gitea.com` and
self-hosted Gitea instances — through the same plan-and-approval safety model as GitHub.

> Want OpsCrew to **provision** a hardened self-hosted Gitea on your server and connect your app
> with an API token and webhooks? See
> [Self-hosted Gitea: provisioning and app integration](gitea-self-hosted.md).

## Prerequisites

- **Gitea version:** Gitea **1.21+** for Actions secrets and variables, and **1.23+** for
  triggering workflows through the API (`workflow_dispatch`, required by `opscrew rollback`,
  `opscrew promote`, and OpsCrew cloud runs).
- **Gitea Actions enabled** on the instance and repository, with at least one `act_runner`
  attached.
- **Personal Access Token (`GITEA_TOKEN`):** create one at
  `https://<your-gitea-host>/user/settings/applications` with:
  - `write:repository` (files, pull requests, deploy keys, Actions secrets/variables/runs/runners)
  - `write:package` (container images in Gitea's OCI package registry)

## Remote detection

`opscrew init` recognises Gitea automatically when `origin` points to:

- `gitea.com`;
- any hostname with a `gitea` DNS label (for example `gitea.company.internal`);
- any custom hostname configured in `GITEA_HOST` (or when `OPSCREW_GIT_PLATFORM=gitea`).

```bash
export GITEA_TOKEN="<your-token>"
# Optional for custom domains that do not contain "gitea":
export GITEA_HOST="git.example.com"
npx opscrew init
```

## Deploy workflow & secrets

- OpsCrew renders the deploy workflow to `.gitea/workflows/opscrew-deploy.yml` (and
  `.gitea/workflows/opscrew-deploy-<env>.yml` for additional environments), based on OpsCrew's
  GitHub Actions workflow template.
- **Registry:** images are pushed to your Gitea instance's built-in OCI container registry
  (`<host>/<owner>/<repo>`, or `cicd.registryHost` when overridden). Both build and server-side
  deploy logins authenticate with `${{ secrets.OPSCREW_REGISTRY_TOKEN || secrets.GITHUB_TOKEN }}`
  (prefixed per environment outside `prod`); export `OPSCREW_REGISTRY_TOKEN` when running
  `opscrew provision` if private registry access needs a package token.
- **Secrets:** Gitea does not have deployment environments, so OpsCrew stores deploy secrets at
  repository scope with per-environment prefixes (`OPSCREW_*` for prod, `OPSCREW_STAGING_*` for
  staging).
- **`runs-on` labels:** standard docker-mode jobs request `ubuntu-latest`; self-hosted OpsCrew
  server runners (`environment.runner: server`) request `opscrew-<app>-<env>` directly.
- **Action mirrors:** OpsCrew keeps commit-pinned shorthand action references, which respect your
  Gitea instance's `[actions] DEFAULT_ACTIONS_URL` setting (default `github`).

## Live verification checklist

Unit tests verify Gitea's REST v1 API (including `POST /actions/runners/registration-token` and
`workflow_dispatch`), workflow rendering, and approval-gated provisioning against fake endpoints.
Before relying on a new Gitea instance:

1. Run `npx opscrew init` with `GITEA_TOKEN` and confirm it signs in against `/api/v1/user`.
2. Verify Actions Secrets and Variables are enabled on the repository.
3. Confirm an `act_runner` matching `ubuntu-latest` (or `opscrew-<app>-<env>:host`) is online and
   can push to `https://<host>/v2/<owner>/<repo>`.
