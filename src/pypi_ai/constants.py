from __future__ import annotations

PROJECT_NAME = "PyPi-AI"
VERSION = "0.1.0"

ASCII_ART = r"""
██████╗ ██╗   ██╗██████╗ ██╗      █████╗ ██╗
██╔══██╗╚██╗ ██╔╝██╔══██╗██║     ██╔══██╗██║
██████╔╝ ╚████╔╝ ██████╔╝██║     ███████║██║
██╔═══╝   ╚██╔╝  ██╔═══╝ ██║     ██╔══██║██║
██║        ██║   ██║     ██║     ██║  ██║██║
╚═╝        ╚═╝   ╚═╝     ╚═╝     ╚═╝  ╚═╝╚═╝
"""

TAGLINE = "Evidence-grounded static scanner for suspicious Python packages."
DOMAIN = "AI + Cybersecurity, Software Supply Chain Security"

DEVELOPERS = [
    {
        "name": "VASANTH ADITHYA",
        "roll": "160123749049",
        "email": "vasanthfeb13@gmail.com",
    },
    {
        "name": "SAI GEETHIKA",
        "roll": "160123749302",
        "email": "yedlasaigeethika37@gmail.com",
    },
]

CITATIONS: dict[str, str] = {
    "CHASE": (
        "Toda, T. and Mori, T. CHASE: LLM Agents for Dissecting Malicious PyPI "
        "Packages. 2025 IEEE/ACM AIware."
    ),
    "PYPA_SDIST": "PyPA source distribution format specification.",
    "PYPA_WHEEL": "PyPA binary distribution wheel format specification.",
    "PYTHON_TARFILE": "Python tarfile extraction filters documentation.",
    "GEMINI": "Google Gemini API structured output documentation.",
    "OLLAMA": "Ollama API and cloud documentation.",
    "MALWARE_EXAMPLES": (
        "Public reports and datasets from Datadog, Unit42, Fortinet, and "
        "ReversingLabs for package-name examples only."
    ),
}

MALICIOUS_PACKAGE_NAME_EXAMPLES = [
    "reallydonothing",
    "jupyter-calendar-extension",
    "calendar-extender",
    "ReportGenPub",
    "Auto-Scrubber",
    "ligitgays",
    "xboxredeemer",
    "syntax-init",
    "xboxlivepy",
    "Ligitkidss",
    "tls-python",
    "zlibxjson",
    "Zebo",
    "Cometlogger",
    "termcolour",
]
