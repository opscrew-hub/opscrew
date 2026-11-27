---
name: opscrew-aws
description: Plan, customize, and deploy apps to AWS managed services with OpsCrew (presets lean/balanced/production-ha, --set overrides, keyless GitHub OIDC, and cost-trap guardrails).
---

# OpsCrew AWS Managed Services

Use this companion skill when the user wants to deploy an application to **Amazon Web Services (AWS)** with OpsCrew.

## Core Rules

1. **Install the optional AWS provider plugin first** (if `opscrew_plugins` shows `aws` is not installed):
   - Give the user the terminal command: `npx opscrew plugin add aws`
   - Never ask the user to paste AWS access keys or secret keys into chat. Recommend `aws sso login` / `AWS_PROFILE` or environment variables set in their own terminal.
2. **Use OpsCrew's single core MCP server (`opscrew`)** — this companion plugin adds AWS workflow guidance and does NOT launch a second MCP server.
3. **Never write raw AWS HCL or run `tofu` / `aws` CLI directly to bypass OpsCrew's plan-hash approval gate.**
   - Design via `opscrew design` (`--option aws-lean|aws-balanced|aws-production-ha`) and customize individual components with repeatable `--set <component>.<field>=<value>` flags.
   - Always surface itemized monthly cost, cost-trap warnings (NAT Gateway ~$32/mo/AZ, CloudWatch log retention, Private CA $400/mo avoidance), and any guardrail exceptions before applying.
4. **Security & DNS defaults:**
   - GitHub Actions deploys MUST use keyless OIDC (`id-token: write`, strict `StringEquals` `sub` claim) — zero stored `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
   - Databases stay private (`publicly_accessible = false`) and encrypted; secret values are written out-of-band to AWS Secrets Manager / SSM Parameter Store and NEVER embedded in Terraform state.
   - When Cloudflare manages DNS alongside AWS ACM, ACM DNS-01 CNAME validation records MUST stay `proxied = false` (DNS only).

