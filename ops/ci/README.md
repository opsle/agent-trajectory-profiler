# CI and Deployment Lifecycle

This repository implements the canonical self-hosted deployment lifecycle:

```
AI -> PR -> TEST -> MERGE -> TEST merged SHA -> DEPLOY -> VERIFY
```

## Structure
- `ops/ci/test`: Runs test suite and static checks
- `ops/ci/deploy <SHA>`: Safely deploys tested release to `/opt/opsle-components/agent-trajectory-profiler`
- `ops/ci/verify <SHA>`: Verifies receipt and tests deployed installation
- `ops/ci/operator-gate`: Pre-flight operator environment validation
- `ops/ci/install-test-runner`: Sets up self-hosted CI runner
- `ops/ci/install-deploy-runner`: Sets up self-hosted deploy runner
- `.github/workflows/ci.yml`: Runs `ops/ci/test` on pull requests and main pushes
- `.github/workflows/deploy.yml`: Deploys only verified merge SHAs on main
