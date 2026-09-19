"""Tests for dependency scanner."""
import pytest
from pathlib import Path

from depscan.scanner import MultiScanner, DependencyParser, Dependency, Vulnerability


class TestDependencyParser:
    def setup_method(self):
        self.parser = DependencyParser()

    def test_parse_cargo_lock(self):
        content = '''
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "tokio"
version = "1.0.0"
'''
        deps = self.parser.parse_cargo_lock(content)
        assert len(deps) == 2
        assert deps[0].name == "serde"
        assert deps[0].version == "1.0.0"
        assert deps[0].ecosystem == "cargo"

    def test_parse_package_lock(self):
        content = '''
{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/express": {
      "version": "4.18.0"
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 2

    def test_parse_requirements_txt(self):
        content = '''
requests==2.28.0
flask>=2.0.0
numpy==1.24.0
'''
        deps = self.parser.parse_requirements_txt(content)
        assert len(deps) == 3

    def test_parse_go_mod(self):
        content = '''
require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.0
)
'''
        deps = self.parser.parse_go_mod(content)
        assert len(deps) == 2

    def test_parse_go_mod_replace_single(self):
        content = '''
require (
    github.com/gin-gonic/gin v1.9.0
    github.com/foo/bar v1.2.3
)

replace github.com/foo/bar => github.com/foo/bar v1.5.0
'''
        deps = self.parser.parse_go_mod(content)
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["github.com/gin-gonic/gin"] == "1.9.0"
        assert dep_map["github.com/foo/bar"] == "1.5.0"

    def test_parse_go_mod_replace_block_and_local(self):
        content = '''
require (
    github.com/a/b v1.0.0
    github.com/c/d v2.0.0
)

replace (
    github.com/a/b => github.com/a/b v1.1.0
    github.com/c/d => ./local/d
)
'''
        deps = self.parser.parse_go_mod(content)
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["github.com/a/b"] == "1.1.0"
        assert dep_map["github.com/c/d"] == "./local/d"

    def test_parse_go_mod_single_require(self):
        content = '''
require github.com/single/mod v0.9.1
replace github.com/single/mod => github.com/single/mod v1.0.0
'''
        deps = self.parser.parse_go_mod(content)
        assert len(deps) == 1
        assert deps[0].name == "github.com/single/mod"
        assert deps[0].version == "1.0.0"

    def test_parse_poetry_lock(self):
        content = '''
[[package]]
name = "django"
version = "4.2.0"

[[package]]
name = "celery"
version = "5.3.0"
'''
        deps = self.parser.parse_poetry_lock(content)
        assert len(deps) == 2

    def test_pipfile_lock_parsing(self):
        content = '''
{
    "_meta": {
        "hash": {"sha256": "abcdef"},
        "pipfile-spec": 6,
        "requires": {"python_version": "3.11"}
    },
    "default": {
        "requests": {
            "hashes": ["sha256:1234"],
            "index": "pypi",
            "version": "==2.31.0"
        },
        "urllib3": {
            "hashes": ["sha256:5678"],
            "version": "==2.0.4"
        },
        "certifi": {
            "hashes": ["sha256:9012"],
            "version": "==2023.7.22"
        }
    },
    "develop": {
        "pytest": {
            "hashes": ["sha256:3456"],
            "version": "==7.4.0"
        },
        "black": {
            "hashes": ["sha256:7890"],
            "version": "==23.7.0"
        }
    }
}
'''
        deps = self.parser.parse_pipfile_lock(content)
        assert len(deps) == 5
        names = {d.name for d in deps}
        assert names == {"requests", "urllib3", "certifi", "pytest", "black"}
        for d in deps:
            assert d.ecosystem == "pypi"

    def test_pipfile_lock_uses_exact_versions(self):
        content = '''
{
    "default": {
        "requests": {"version": "==2.31.0"}
    }
}
'''
        deps = self.parser.parse_pipfile_lock(content)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"

    def test_pipfile_lock_malformed_json(self):
        content = "{ invalid json"
        deps = self.parser.parse_pipfile_lock(content)
        assert deps == []

    test_plfile_lock_parsing = test_pipfile_lock_parsing
    test_plfile_lock_uses_exact_versions = test_pipfile_lock_uses_exact_versions
    test_plfile_lock_malformed_json = test_pipfile_lock_malformed_json


class TestMultiScanner:
    def setup_method(self):
        self.scanner = MultiScanner()

    

    def test_typosquat_detection(self):
        dep = Dependency(name="raquests", version="1.0.0", ecosystem="pypi")
        assert self.scanner.check_typosquat(dep) is True
        assert dep.is_typosquat
        assert dep.typosquat_target == "requests"

    def test_no_typosquat_for_known_package(self):
        dep = Dependency(name="requests", version="2.28.0", ecosystem="pypi")
        assert self.scanner.check_typosquat(dep) is False


class TestScanDirectory:
    def test_scan_nonexistent(self):
        scanner = MultiScanner()
        deps = scanner.scan_directory("/nonexistent")
        assert deps == []

    def test_scan_current_dir(self, tmp_path):
        # Create test files
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        (tmp_path / "go.mod").write_text("module test\nrequire github.com/test/test v1.0.0\n")

        scanner = MultiScanner()
        deps = scanner.scan_directory(str(tmp_path))
        assert len(deps) >= 1

    def test_scan_pipfile_lock(self, tmp_path):
        lock_file = tmp_path / "Pipfile.lock"
        lock_file.write_text('{"default": {"requests": {"version": "==2.31.0"}}}')
        scanner = MultiScanner()
        deps = scanner.scan_file(str(lock_file))
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[0].ecosystem == "pypi"

        dir_deps = scanner.scan_directory(str(tmp_path))
        assert len(dir_deps) == 1
        assert dir_deps[0].name == "requests"



class TestDependency:
    def test_is_vulnerable_false(self):
        dep = Dependency(name="test", version="1.0.0", ecosystem="pypi")
        assert dep.is_vulnerable is False

    def test_is_vulnerable_true(self):
        dep = Dependency(name="test", version="1.0.0", ecosystem="pypi")
        dep.known_vulnerabilities.append(
            Vulnerability(id="GHSA-xxx", severity="HIGH", description="test")
        )
        assert dep.is_vulnerable is True
