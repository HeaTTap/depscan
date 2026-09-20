"""Tests for depscan output formatters."""
from depscan.formatter import MarkdownFormatter


def test_format_summary_basic():
    results = {
        "total": 5,
        "typosquats": [],
        "by_ecosystem": {"npm": 3, "cargo": 2}
    }
    md = MarkdownFormatter().format_summary(results)
    assert "# Dependency Scan Report" in md
    assert "5" in md
    assert "| npm |" in md
    assert "| cargo |" in md
    assert "✅ Scan Complete" in md or "[OK] Scan Complete" in md


def test_format_summary_with_typosquats():
    from depscan.scanner import Dependency
    dep = Dependency(name="vreb-ui", version="1.0.0", ecosystem="npm")
    dep.typosquat_target = "vue"
    results = {
        "total": 3,
        "typosquats": [dep],
        "by_ecosystem": {"npm": 3}
    }
    md = MarkdownFormatter().format_summary(results)
    assert "vreb-ui" in md
    assert "Potential Typosquats" in md
    assert "vue" in md


def test_format_full():
    results = {
        "total": 10,
        "typosquats": [],
        "by_ecosystem": {"npm": 5, "pypi": 3, "cargo": 2}
    }
    md = MarkdownFormatter().format_full(results)
    assert "# Dependency Scan Report" in md
    assert "Detailed Results" in md
    assert "### npm" in md
    assert "### pypi" in md
    assert "### cargo" in md


def test_empty_results():
    results = {"total": 0, "typosquats": [], "by_ecosystem": {}}
    md = MarkdownFormatter().format_summary(results)
    assert "0" in md
    assert "✅ Scan Complete" not in md
