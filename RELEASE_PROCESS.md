# Release Process

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Pre-release Versions

- `0.1.0-alpha`: Initial development
- `0.1.0-beta`: Feature complete, testing
- `0.1.0-rc.1`: Release candidate

## Release Checklist

### Pre-release

1. [ ] All tests pass: `cargo test --workspace`
2. [ ] Clippy clean: `cargo clippy --workspace -- -D warnings`
3. [ ] Format clean: `cargo fmt --all -- --check`
4. [ ] Audit clean: `cargo audit`
5. [ ] Deny clean: `cargo deny check`
6. [ ] Documentation updated
7. [ ] CHANGELOG.md updated
8. [ ] Version bumped in Cargo.toml

### Release

1. [ ] Create release branch: `release/v{VERSION}`
2. [ ] Final test run
3. [ ] Build release binaries:
   - Linux amd64
   - Linux arm64
   - macOS amd64
   - macOS arm64
   - Windows amd64
4. [ ] Build Docker image
5. [ ] Generate checksums
6. [ ] Generate SBOM
7. [ ] Sign artifacts
8. [ ] Create git tag: `v{VERSION}`
9. [ ] Push tag
10. [ ] Create GitHub release (draft)

### Post-release

1. [ ] Verify release binaries work
2. [ ] Verify Docker image works
3. [ ] Update documentation site
4. [ ] Publish release announcement
5. [ ] Update dependent projects

## Release Automation

Releases are automated via GitHub Actions:

1. Push a tag matching `v*` triggers the release workflow
2. Builds binaries for all platforms
3. Builds and pushes Docker image
4. Creates GitHub release with artifacts

## Hotfix Process

1. Create hotfix branch from release tag
2. Apply fix
3. Test thoroughly
4. Bump patch version
5. Create new release

## Rollback Procedure

1. Identify the issue
2. Revert to previous version:
   ```bash
   # Docker
   docker pull osmiridium/osmiridium:v{PREVIOUS}
   
   # Binary
   curl -sSL https://github.com/osmiridium/osmiridium/releases/download/v{PREVIOUS}/osmiridium-x86_64-unknown-linux-gnu.tar.gz
   ```
3. Notify users
4. Investigate root cause
5. Fix and release new version
