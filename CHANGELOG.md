# Changelog

## 0.2.5

- **Fixed: every release failed.** The release workflow's version check was a
  YAML plain value that folds into one line, so the script never ran. It is a
  block (`run: |`) now, and a test reads the workflow, runs the checks with a
  faked tag and commit, and fails if a `run:` ever folds again.
- The release workflow also refuses a tag whose commit is not on `main`, and
  runs the tests from the built sdist (CI does the same on every change, and
  also runs Python 3.14).
- **Fixed: a secret scrubber that failed open.** A JSON Web Token with a part
  longer than 4096 characters was printed as it was. The limit is gone; the
  scan is still linear (a 5-million-character case is covered).
- Fewer false alarms: `--max-tokens 100000`, `--token-limit`, `--tokens` and
  other options that hold an amount are no longer reported as a secret in the
  arguments; a mount of `/srv/.dockerfiles` or `/data/my.configs` is not a
  mount of `~/.docker` or `~/.config` (whole folder names are compared); and
  options after the image name (`docker run img --privileged`) belong to the
  program in the container, not to Docker. A data file named `.bin` is not code.
- Fewer misses: macOS per-user temporary folders (`/var/folders`,
  `/private/var/folders`), `sh -c /tmp/evil`, `uvx --from /tmp/x.whl`,
  `file:///tmp/x.js`, Windows paths with `/`, a password in a URL argument
  (`postgres://user:pass@host/db`) and the short password options of
  `sshpass -p`, `mysql -pSECRET`, `redis-cli -a` and `curl -u user:pw`.
- Tests no longer depend on where the Python interpreter is installed.

## 0.2.4

- **Fixed a hang:** the JSON Web Token pattern in the secret scrubber took time
  quadratic in the length of a run of `eyJ...-` blocks (a 40,000-block
  `args` entry ran for over 150 s). JWTs are now found in linear time (limits
  4096 characters per segment); the timing test compares n with 4n instead of
  using a wall-clock limit, and a 400,000-block case is covered. A package name
  or version is cut at 80 characters in messages, and no message exceeds 1,500.
- **Fixed a way past `--fail-on high`:** a tool description longer than
  100,000 characters was only read to that point and reported as medium, so an
  instruction behind padding escaped. It is now high.
- New checks: `secret-in-args` (a token or key written into the arguments),
  `privileged-launch` (`sudo`, `doas`, ...), `container-escape` (`docker run`
  with `--privileged`, the runtime socket, a mount of `/` or `~/.ssh`, host
  namespaces, ...), `temp-binary` (code run from `/tmp`, `%TEMP%`, ...). What is
  still not covered is listed under Limitations.
- Shell script text is read up to 4,000,000 characters per run (all servers
  together); beyond that an entry is a visible `detector-error`. A script is
  read once per entry instead of once per check.
- README: use the `mcp-audit` command everywhere (`python3 -m mcp_audit` runs a
  `mcp_audit/` package from the current directory, which in a cloned repository
  is that repository's code); the first screen says the advisory feed holds 3
  curated entries offline and `--online` queries OSV; never run `--deep` on a
  config you did not write.
- Package metadata (license expression, keywords, classifiers, URLs, authors),
  `setuptools>=77`, GitHub Actions CI and trusted-publishing release workflow.

## 0.2.3 and earlier

See the git history.
