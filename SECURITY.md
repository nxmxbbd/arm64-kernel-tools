# Security Policy

## These tools are inherently security-sensitive

This toolkit reads and writes physical memory via `/dev/mem`. It patches running kernel code and data structures. This is powerful and dangerous by design. The security model assumes you have root access on a device you own and are making deliberate modifications.

## What is NOT a vulnerability

- **Access to `/dev/mem`**: The tools intentionally use `/dev/mem` to read and write physical memory. That is the entire point. Do not report this as a vulnerability.
- **Ability to modify kernel text/data**: This is the core functionality, not a bug.
- **Requirement for root access**: The tools require root. This is a feature.

## What IS a vulnerability

If you find a bug in the tools themselves that could cause unintended behavior, we want to know. Examples:

- A tool writes to the wrong physical address due to a calculation error
- A safety check can be bypassed unintentionally
- A tool misparses `/proc/kallsyms` and targets the wrong symbol
- Buffer overflows or injection issues in the tools' own code

## Reporting

- **GitHub Issues**: Open an issue on this repository. For most bugs this is fine — the tools are open source and the attack surface is "you already have root."
- **Email**: If you believe the issue is sensitive enough to warrant private disclosure, contact the maintainers directly.

Please include:
- Description of the issue
- Steps to reproduce
- Affected tool(s) and version/commit
- Your assessment of impact

We will acknowledge reports promptly and aim to fix confirmed issues quickly.
