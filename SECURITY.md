# Security policy

## Intended use

Authorized, defensive reverse engineering, software compatibility research, binary education, and forensic triage. Analyze only files you are permitted to inspect.

## Model and third-party tools

The core analyzer never executes the subject binary. It is not an isolation sandbox. Running third-party Ghidra is explicitly opt-in and has a distinct trust boundary: install a trusted Ghidra release and use an isolated virtual machine for unknown or hostile samples. Capstone disassembly is in-process and parses untrusted machine code; maintain updates. Ollama connections are restricted to HTTP loopback; no outbound AI provider is configured.

AI responses can hallucinate or misinterpret data. Binary-embedded text may include adversarial prompt injection attempts; ARES labels data as untrusted and separates suggestions from evidence, but does not claim comprehensive prompt-injection resistance.

## Sensitive reports

Reports may include personally sensitive file names, paths, extracted strings, function names, and AI summaries. Review and sanitize reports before sharing. ARES does not collect usage metrics, add telemetry, or upload binary data.

## Reporting vulnerabilities

Do not disclose unpatched vulnerabilities publicly. Open a private GitHub security advisory for the repository owner where supported, or contact the maintainer privately through GitHub. Provide a minimal reproducer, affected version, and impact. Please never attach live malware publicly.

## Release maturity

Version 0.1.0 is an engineering preview. Builds are currently unsigned, not notarized, and not independently penetration-tested. Do not treat it as hardened production malware-analysis infrastructure.
