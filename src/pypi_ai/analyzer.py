from __future__ import annotations

import ast
import base64
import math
from pathlib import Path

from pypi_ai.models import Finding, PackageMetadata
from pypi_ai.rules import RULES, Rule


class StaticAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        file_path: Path,
        root: Path,
        source: str,
        metadata: PackageMetadata,
        start_index: int,
    ) -> None:
        self.file_path = file_path
        self.root = root
        self.lines = source.splitlines()
        self.metadata = metadata
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, int, int, str]] = set()
        self._next_index = start_index

    def visit_Attribute(self, node: ast.Attribute) -> None:
        dotted = self._dotted_name(node)
        if dotted.startswith("os.environ"):
            self._add("PY001_ENV_ACCESS", node)
        if dotted.startswith(("subprocess.", "os.system")):
            self._add("PY002_SUBPROCESS", node)
        if dotted.startswith(("socket.", "requests.", "urllib.request.", "http.client.")):
            self._add("PY003_NETWORK_CLIENT", node)
        if dotted.startswith(("base64.", "binascii.")):
            self._add("PY004_OBFUSCATION", node)
        if dotted.startswith(("pickle.", "marshal.")):
            self._add("PY006_UNSAFE_DESERIALIZATION", node)
        if dotted.startswith(("ctypes.", "cffi.")):
            self._add("PY007_NATIVE_CODE", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._dotted_name(node.func)
        if name in {"eval", "exec", "compile", "__import__"}:
            self._add("PY005_DYNAMIC_EXEC", node)
        if self.file_path.name == "setup.py" and name in {
            "setup",
            "subprocess.call",
            "subprocess.run",
            "os.system",
        }:
            self._add("PY008_INSTALL_TIME", node)
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string(arg.value, node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self._check_string(node.value, node)
        self.generic_visit(node)

    def _check_string(self, value: str, node: ast.AST) -> None:
        if len(value) >= 24 and _entropy(value) >= 4.2:
            self._add("PY004_OBFUSCATION", node)
            return
        if len(value) >= 8:
            try:
                base64.b64decode(value, validate=True)
            except Exception:
                return
            self._add("PY004_OBFUSCATION", node)

    def _add(self, rule_id: str, node: ast.AST) -> None:
        rule = RULES[rule_id]
        line_start = getattr(node, "lineno", 1)
        line_end = getattr(node, "end_lineno", line_start)
        snippet = self._snippet(line_start, line_end)
        dedupe_key = (
            rule_id,
            self.file_path.as_posix(),
            line_start,
            line_end,
            snippet,
        )
        if dedupe_key in self._seen:
            return
        self._seen.add(dedupe_key)
        finding = _finding_from_rule(
            rule=rule,
            index=self._next_index,
            file_path=self.file_path,
            root=self.root,
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
            metadata=self.metadata,
        )
        if finding not in self.findings:
            self.findings.append(finding)
            self._next_index += 1

    def _snippet(self, line_start: int, line_end: int) -> str:
        start = max(line_start - 1, 0)
        end = min(line_end, len(self.lines))
        return "\n".join(self.lines[start:end]).strip()

    def _dotted_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = self._dotted_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        if isinstance(node, ast.Call):
            return self._dotted_name(node.func)
        return ""


def analyze_python_file(
    file_path: Path,
    root: Path,
    metadata: PackageMetadata,
    start_index: int,
) -> list[Finding]:
    source = file_path.read_text(encoding="utf-8", errors="replace")
    analyzer = StaticAnalyzer(file_path, root, source, metadata, start_index)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    analyzer.visit(tree)
    return analyzer.findings


def _finding_from_rule(
    rule: Rule,
    index: int,
    file_path: Path,
    root: Path,
    line_start: int,
    line_end: int,
    snippet: str,
    metadata: PackageMetadata,
) -> Finding:
    try:
        relative = file_path.relative_to(root).as_posix()
    except ValueError:
        relative = file_path.as_posix()
    return Finding(
        finding_id=f"F{index:03d}",
        rule_id=rule.rule_id,
        severity=rule.severity,
        category=rule.category,
        file_path=relative,
        line_start=line_start,
        line_end=line_end,
        snippet=snippet,
        message=rule.message,
        confidence=0.85,
        tags=list(rule.tags),
        citations=list(rule.citations),
        package_name=metadata.name,
        package_version=metadata.version,
    )


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
