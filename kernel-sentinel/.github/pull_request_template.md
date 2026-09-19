## Summary

<!-- Brief description of what this PR does -->

## Motivation

<!-- Why is this change needed? What problem does it solve? Link related issues with # -->

## Test plan

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo fmt --all -- --check` passes
- [ ] eBPF objects compile (5 tiers: modern / legacy / ancient / ancient_nobtf / legacy_nobtf)
- [ ] Manually tested on:

## Checklist

- [ ] Code follows the project style guidelines (rustfmt + clippy clean)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] Self-reviewed the code
- [ ] Added/updated tests for new functionality
- [ ] No new compiler warnings introduced
- [ ] Documentation updated if needed
