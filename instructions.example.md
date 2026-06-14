# Example aurscan extra instructions
#
# Copy to ~/.config/aurscan/instructions.md (or point AURSCAN_INSTRUCTIONS at it).
# This text is APPENDED to the built-in auditor instructions — it sharpens the
# auditor, it cannot weaken the core rules or the prompt-injection hardening.

Apply extra scrutiny to provenance and reputation:

- Treat a package with zero or very few votes as untrusted by default; require a
  clear, legitimate technical reason for any network access, package-manager
  call, or code execution during build or install.
- If the reputation signals show a recent maintainer change, raise the verdict
  by one level (OK -> SUSPICIOUS, SUSPICIOUS -> MALICIOUS) unless the diff is
  trivially benign (version bump, checksum update, dependency rename).
- Flag any change that has no obvious advantage to the user or reason to exist:
  a "patch"/"fix"/"optimization" that does not plausibly serve the package's
  stated function, an added source unrelated to upstream, or build steps a
  normal build would never need. State explicitly what legitimate purpose is
  missing.
- For -bin packages, the binary should come from the project's official release
  host; a download from a personal account or unrelated domain is a red flag.
