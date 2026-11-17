Public legislative access audit — one-time cloud test

Purpose: test the routes that depend on a browser or FTP from a standard
GitHub-hosted Ubuntu runner. This is an audit harness, not a production
collector. It has no schedule and does not send notifications.

Files in the chosen repository:
  legislation-audit/runner.py
  .github/workflows/legislative-access-audit.yml

The workflow runs on relevant pushes to main or the isolated audit branch,
on a manual workflow dispatch, or when the repository becomes public.
A job guard skips execution while the repository is private, so private
runner billing cannot be incurred by this audit. There is no schedule.

Checks:
  CT: anonymous FTP CSV inventory
  TX: anonymous FTP session/directory enumeration and two introduced texts
  VA: anonymous complete CSV plus public browser and introduced PDFs
  IN: fresh public browser inventory and two introduced PDFs
  CA: anonymous range transport to the official bulk ZIP
  US: official introduced XML control

No state accounts, state API keys, paid service, saved browser state,
proxy service, CAPTCHA solution or stealth plugin is used. The browser
starts with a new anonymous context. Standard public-repository hosted
runners are free under GitHub's current published pricing. The workflow
uses no artifact upload or cache, avoiding an additional storage allocation.
Only compact counts, hashes and outcomes are retained in job logs. Original
Virginia CSV bytes are held only during the check and are not published.

The result records GitHub run ID, commit, runner environment and timestamps.
Every unsuccessful check makes the job fail. A successful job establishes
point-in-time cloud access, not sustained uptime or all-bill completeness.

Sources:
https://docs.github.com/en/billing/concepts/product-billing/github-actions
https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule

No recurring collector should be enabled before outstanding audit failures
are resolved and inventory/session evidence has been reviewed.

