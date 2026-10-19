---
id: docker-compose-diagnostics
name: Docker Compose Diagnostics
triggers:
  - docker
  - compose
  - container
  - unhealthy
  - oom
  - volume permission
  - docker compose
allowed_paths:
  - "~/.config/lnta/*.md"
required_bins:
  - docker
  - dmesg
context_cmd: docker --version && docker compose version
verify_cmd: docker compose config --quiet && echo "compose.yaml valid"
---
# Docker Compose Diagnostics

Inspect unhealthy containers, diagnose port collisions, detect cgroup OOM kills, identify volume permission mismatches, and validate `compose.yaml` syntax.

## What this pack covers

- Listing containers with `docker ps -a` and filtering by health/status
- Inspecting container logs via `docker logs <container>`
- Checking for OOM kills in kernel ring buffer: `dmesg -T | grep -i oom`
- Diagnosing port collisions with `ss -tulpn` and `docker port <container>`
- Identifying volume permission issues: `ls -la /var/lib/docker/volumes/<volume>/_data`
- Validating compose file syntax with `docker compose config`
- Checking resource limits: `docker stats --no-stream`

## Safety

This pack is **read-only by default**. It inspects Docker state but does not start, stop, remove, or modify containers, volumes, or networks. All diagnostics run through `inspect_system` in the sandbox. If a fix requires `docker compose up/down/restart`, use `mutate_system` with explicit approval.

## Common diagnostic workflows

### Unhealthy container
```bash
docker ps -a --filter health=unhealthy
docker inspect <container> --format '{{json .State.Health}}'
docker logs <container> --tail 100
```

### Port collision
```bash
ss -tulpn | grep :<port>
docker port <container>
# Check if host port already in use
```

### OOM kill detection
```bash
dmesg -T | grep -i -e oom -e "out of memory" -e "killed process"
# Or check container directly
docker inspect <container> --format '{{.State.OOMKilled}}'
```

### Volume permission mismatch
```bash
docker volume inspect <volume>
ls -la /var/lib/docker/volumes/<volume>/_data
# Compare UID/GID with container user
```

### Compose validation
```bash
docker compose config        # Validates and renders merged config
docker compose config --quiet # Exit code only (0 = valid)
```

## Verification

The `verify_cmd` runs `docker compose config --quiet` which exits 0 if the compose file is syntactically valid and all referenced images/services are resolvable. This catches YAML syntax errors, missing environment variables, and invalid service configurations before deployment.