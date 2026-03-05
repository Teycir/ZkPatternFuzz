## CVE Fixture Bank

These fixtures are intentionally small, local regression targets for
`templates/known_vulnerabilities.yaml`.

They exist to keep the CVE regression lane portable:

- no external drive mounts
- no workstation-specific absolute paths
- no heavyweight benchmark-only circuits for basic regression wiring

They are not intended to model full production circuits. They provide stable,
in-repo execution targets so the regression database can be exercised on a
clean clone.
