# AGENTS.md — Valkyrie Project Rules

These rules apply to every AI agent working in this repository (Antigravity, or any other compatible tool). Read this fully before making changes. These rules exist to keep the build aligned with the project's planning documents (see `/docs` if present, or ask the human collaborator for the SRS).

## Project Summary

Valkyrie is a web-based security tool that scans GitHub repositories for vulnerable
packages and insecure code patterns, then uses AI to explain each risk in plain English
and suggest a fix. Built with ASP.NET Core (C#), individual project, solo developer.

## Hard Scope Boundaries — Do Not Violate

- **Ecosystem support is limited to npm and NuGet (full support) and Python (partial — code pattern scanning only, no package vulnerability checks).** Do not add support for, or write parsers for, any other ecosystem (Java/Maven, Go, Ruby, PHP, etc.) unless explicitly asked.
- **No automatic code fixing.** The tool suggests fixes in text/UI only. Never write code that modifies the user's repository, opens pull requests, or pushes commits back to GitHub.
- **No private repository scanning.** Only public GitHub repos are in scope. Do not implement GitHub OAuth or private repo access unless explicitly asked.
- **No real-time or continuous monitoring.** This is a scan-on-demand tool only. Do not add background jobs, webhooks, or polling that scan repos automatically.
- **Single user role only.** There is no Admin role and no admin UI. Do not scaffold admin dashboards, admin-only pages, or multi-role permission systems.
- **No pagination on list views** (scan history, package lists, code issue lists) at this stage. These lists are small (a handful to a few dozen items per user). Do not add pagination logic unless explicitly asked.

If a task seems to require violating one of the above, stop and ask the human collaborator before proceeding — do not silently expand scope.

## Tech Stack — Use These, Not Alternatives

- **Backend**: ASP.NET Core (C#), .NET 10 (confirmed installed version — if a different version is detected in the project file, match that instead of assuming .NET 8)
- **Frontend**: Razor Pages/Views + Bootstrap 5. Do not introduce React, Vue, Angular, or any SPA framework.
- **Database**: SQL Server via Entity Framework Core (Code-First). Local development uses SQL Server LocalDB.
- **Auth**: ASP.NET Identity, session cookies. Do not implement JWT or any token-based auth.
- **External APIs**:
  - GitHub REST API (repository file access) — token stored via .NET User Secrets, never hardcoded
  - OSV.dev API (package vulnerability lookup) — free, public, no key needed
  - AI explanations via **AgentRouter** (Anthropic-compatible endpoint), not a direct Anthropic API key. API key stored via .NET User Secrets, never hardcoded.
- **Architecture style**: Modular Monolith. One deployable app, organized into clearly separated folders/modules (Repository Intake, Dependency Scanning, Code Pattern Scanning, AI Explanation, Reporting/Dashboard, User Accounts). Do not split into microservices or separate deployable services.
- **Communication**: REST only. No GraphQL, no WebSockets, no message queues.

## Secrets & Configuration

- **Never hardcode API keys, tokens, or connection strings** in any committed file.
- Use **.NET User Secrets** for local development (`dotnet user-secrets`) and environment variables for anything deployed.
- If a task requires a secret that isn't yet configured, stop and tell the human collaborator what's needed rather than inventing a placeholder that looks like a real key.

## Database Schema — Follow This Exactly

Four core tables (plus ASP.NET Identity's built-in user tables):

- **ScanResults**: Id, UserId (FK), RepositoryUrl, RepositoryName, EcosystemsDetected, SecurityGrade, TotalIssuesFound, ScannedAt, Status (enum: Completed, PartialFailure, Failed)
- **VulnerablePackages**: Id, ScanResultId (FK), PackageName, Ecosystem (enum: npm, NuGet, Python), InstalledVersion, SafeVersion, Severity (enum: Critical, High, Medium, Low), Description, AiExplanation, AiFixSuggestion
- **CodeIssues**: Id, ScanResultId (FK), FileName, LineNumber, IssueType (enum: HardcodedSecret, SqlInjectionRisk, ExposedConfig, InsecureHttp), CodeSnippet, Severity, AiExplanation, AiFixSuggestion

Relationships: Users (1)→(many) ScanResults; ScanResults (1)→(many) VulnerablePackages; ScanResults (1)→(many) CodeIssues.

Do not add extra tables, rename fields, or change relationship cardinality without flagging it to the human collaborator first — this schema was deliberately planned against the app's workflows.

## Required Behaviors (from workflow planning)

- **Python repos**: if only `requirements.txt` is found (no `package.json` or `.csproj`), still run the code pattern scanner, but the Results page MUST show a prominent, unmissable banner stating that package vulnerability scanning is disabled for Python. This is a successful scan outcome, not an error — never silently treat it as fully scanned, and never fail the scan because of it.
- **Fully unsupported ecosystem** (no `package.json`, `.csproj`, or `requirements.txt` found at all): stop the scan before downloading further, and show a clear message naming what IS supported. Do not generate a partial or empty report.
- **Repository size limits**: enforce a file-size/file-count threshold before downloading repo contents, to avoid attempting to process extremely large repositories.
- **Monorepos** (multiple ecosystems in one repo): scan all supported ecosystems found and combine into one report, but group results by ecosystem in the UI rather than mixing them together.
- **Zero issues found**: this is a valid, positive result (high grade, "no issues found" state) — never treat an empty issue list as an error or a broken state.
- **Partial AI/API failures**: if OSV.dev or the AI API times out or fails for some issues, show the issues that succeeded with a note that some couldn't be analyzed, rather than failing the entire scan.
- **Login**: lock the account after 5 failed attempts for 5 minutes. Use a generic "Invalid email or password" error — never reveal whether an email exists in the system.

## Regex Code Scanning — Keep Simple

Per identified project risk: writing Regex to reliably catch security issues (e.g. SQL injection) without excessive false positives is hard. For this project's scope:
- Favor simple, conservative patterns (e.g. flagging raw string concatenation directly into a SQL keyword) over comprehensive pattern coverage.
- Accept missing some edge cases (false negatives) in exchange for not overwhelming users with false positives.
- Do not attempt to build a comprehensive static analysis engine — that is explicitly out of scope.

## Workflow & Git Conventions

- One GitHub Issue per feature/task. Reference the issue number in commits and PRs (e.g. `Closes #4`).
- Create a new branch per issue (e.g. `feature/github-api-integration`). Do not commit directly to `main` except for the initial project scaffold.
- Write a clear PR description summarizing what changed and why, before merging.
- Keep commits scoped to one logical change at a time rather than one giant commit per feature.

### PR-First Rule — MANDATORY

**Never merge a feature branch into `main` directly. Never run `git merge` or `git push origin main` for feature work.**

The correct end-of-feature workflow is always:
1. Commit all changes on the feature branch (e.g. `feature/my-feature`).
2. Push **only the feature branch** to origin: `git push origin feature/my-feature`
3. Stop there. Tell the human collaborator that the branch is pushed and ready for a Pull Request on GitHub.
4. The human collaborator reviews and merges the PR through the GitHub web interface.

If the human collaborator says words like "push to main", "merge it", or "deploy" — interpret this as a request to push the feature branch and open a PR, **not** to merge directly into `main`. Confirm with them before doing any direct merge to `main`.

## When Uncertain

If a request from the human collaborator seems to conflict with anything in this file, point out the conflict and ask for clarification rather than guessing or silently picking a side. This file reflects deliberate planning decisions (see the project's Software Requirements Specification) — treat it as the source of truth over general best-practice assumptions.
