# Security policy

idlogin handles sign-in for other applications, so we take reports seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private
vulnerability reporting: open
<https://github.com/velixio/idlogin/security/advisories/new> (the
"Report a vulnerability" button on the repository's Security tab).

Do not open a public issue, pull request or discussion for a security
problem. Include what you found, how to reproduce it, the version or commit,
and the impact you expect. We will acknowledge the report, keep you informed
while we investigate, and credit you in the advisory unless you prefer not to
be named.

## Scope

In scope: the code in this repository (the idlogin service, `idlogin setup`,
and the deploy files and scripts). Vulnerabilities in Zitadel itself should go
to the Zitadel project. Configuration mistakes in a particular deployment
(for example an exposed login-client token) are the operator's to fix, but
tell us if our defaults or documentation made them likely.

## Supported versions

Until the first stable release, only the latest commit on `main` and the
latest tag receive fixes.
