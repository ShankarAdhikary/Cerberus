# Kali Linux verification fixture

This directory is a deliberately small project for testing Cerberus locally.
It contains one npm lockfile and one Python requirements file with packages
that OSV.dev may report as vulnerable. The expected result is normally a
non-zero exit code when using `--fail-on high`.

From the Cerberus checkout:

```bash
dep-gate --project verification/kali-project --fail-on high
dep-gate --project verification/kali-project.zip --fail-on high
```

The scanner needs network access to `https://api.osv.dev`. A blocked gate is
an expected result for this fixture; do not use it as a production dependency
file.

To inspect the exit code:

```bash
dep-gate --project verification/kali-project --fail-on high
echo $?
```

Expected exit codes:

- `1`: vulnerabilities at or above `high` were found.
- `0`: no blocking vulnerability was returned by OSV.dev.
- `2`: invalid command or input.
