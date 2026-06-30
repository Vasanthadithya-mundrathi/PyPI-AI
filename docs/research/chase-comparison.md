# CHASE Comparison

## Summary

CHASE is the research benchmark for this continuation branch. It introduces a
Collaborative Hierarchical Agents for Security Exploration architecture that uses a
Plan-and-Execute coordinator, specialized worker agents, and deterministic security tools
to reduce hallucination and context confusion in LLM-based malicious package analysis.

The CHASE paper reports evaluation on 3,000 packages, with 98.4% recall, 0.08% false
positive rate, and 4.5-minute median analysis time per package. PyPi-AI Agent uses those
ideas as a research backbone but changes the product target.

## Comparison Matrix

| Area | CHASE | PyPi-AI stable project | PyPi-AI Agent branch |
|---|---|---|---|
| Primary goal | Malicious PyPI package dissection | Static evidence scanner | Developer-side supply-chain decision support |
| Architecture | Multi-agent Plan-and-Execute | CLI scanner pipeline | Supervisor plus worker agents |
| Static analysis | Yes | Yes | Yes |
| Dynamic analysis | Tool-assisted analysis | No host execution | Docker sandbox probe |
| Evidence grounding | Report evidence and deterministic tools | Evidence IDs and citations | Evidence IDs, sandbox telemetry, audit result |
| Time target | 4.5-minute median | Fast static CLI scans | 300-second package budget |
| User | Security analyst / screening system | Student/demo/reviewer/developer | Developer deciding install/update/isolate |
| Output | Analysis report | JSON/HTML/PDF scan reports | Agent report with remediation |

## Contribution Statement

Unlike CHASE, which focuses on malware dissection, PyPi-AI Agent focuses on
developer-side supply-chain decision support: whether a package should be installed,
blocked, updated, replaced, or isolated.

## Why DySec Matters

DySec motivates the branch's dynamic layer. It argues that metadata inspection and static
code analysis can miss install-time and runtime behavior. PyPi-AI Agent therefore keeps
the stable static scanner, but adds a Docker sandbox path to collect behavior signals in a
bounded environment.

## Sources

- CHASE: https://arxiv.org/abs/2601.06838
- DySec: https://arxiv.org/abs/2503.00324
