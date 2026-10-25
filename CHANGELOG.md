# Changelog

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
