# ToolHive Security Assessment — Verified Edition

**Independent Security Review of Stacklok ToolHive v0.9.3**

---

| Field | Detail |
|-------|--------|
| **Target** | ToolHive v0.9.3 (Desktop App + CLI) |
| **Vendor** | Stacklok, Inc (Apple Team ID: XMNPBXU9PV) |
| **Build** | 2026-02-09 15:20:57 UTC, Go 1.25.7, darwin/arm64 |
| **Commit** | 3074fba189cafa48666f455f70700123d18500c4 |
| **Assessed by** | Philippe Bogaerts / RadarSec |
| **Date** | February 15, 2026 |
| **Scope** | Local macOS desktop installation, API surface, container network isolation, MCP proxy endpoints |
| **Methodology** | Each finding verified against fresh default installations using three-way comparison testing (DEFAULT / NETWORK / ISOLATED) |

---

## 1. Executive Summary

ToolHive by Stacklok is an open-source MCP (Model Context Protocol) server manager that deploys MCP servers inside isolated containers (Docker/Podman). It is distributed as an Electron desktop app (ToolHive Studio) and a Go CLI binary (`thv`).

This is a **revised assessment** that corrects and refines the initial review by systematically verifying each finding against default behavior. Every finding is classified as:

- **DEFAULT BEHAVIOR** — occurs on a fresh installation with no user customization
- **NON-DEFAULT** — requires user action or configuration to trigger
- **NON-EXISTING** — initially suspected but disproved during verification

The most significant discovery during verification was that ToolHive's permission profile system (`"outbound": {}` vs `"insecure_allow_all": true`) is **cosmetically different but functionally identical** — both place containers on a Docker network with `Internal: false`, granting full outbound access including to the host machine. Only the `--isolate-network` flag (which defaults to `false`) creates actual network isolation.

### Risk Summary

| Severity | Count | Classification | Key Areas |
|----------|-------|----------------|-----------|
| **CRITICAL** | 1 | DEFAULT | Container-to-host lateral movement via ToolHive MCP control plane |
| **HIGH** | 2 | DEFAULT | Permission profiles are cosmetic; unhardened container images |
| **MEDIUM** | 3 | 1 DEFAULT, 2 NON-DEFAULT | Log growth; telemetry; kubeconfig exposure |
| **LOW** | 3 | DEFAULT | Unauthenticated local API; directory permissions; Sentry integration |
| **INFO** | 4 | POSITIVE | Code signing; encrypted secrets; localhost binding; OIDC support |

---

## 2. Verification Methodology

To distinguish default behavior from user misconfiguration, three containers were launched with identical base images but different configuration:

| Test | Command | Permission Profile | Docker Network | Internet | ToolHive API |
|------|---------|-------------------|----------------|----------|-------------|
| **DEFAULT** | `thv run filesystem -- /tmp` | `"outbound": {}` | `toolhive-external` (Internal: false) | **YES** | **YES** |
| **NETWORK** | `thv run filesystem --permission-profile network -- /tmp` | `"insecure_allow_all": true` | `toolhive-external` (Internal: false) | **YES** | **YES** |
| **ISOLATED** | `thv run filesystem --isolate-network -- /tmp` | `"outbound": {}` | `toolhive-*-internal` (Internal: true) | **NO** (403) | **NO** (403) |

**Key insight:** DEFAULT and NETWORK produce identical network behavior. The permission profile string in the runconfig changes, but the Docker network assignment does not. Both land on `toolhive-external` with unrestricted egress. Only `--isolate-network` creates a Docker-internal network that blocks outbound traffic.

---

## 3. Findings

### Finding 1: Lateral Movement via host.docker.internal to ToolHive MCP Control Plane — CRITICAL

**Classification: DEFAULT BEHAVIOR**

A containerized MCP server launched with default settings (`thv run <name> -- /path`) can reach the ToolHive MCP control plane on `host.docker.internal:50444` and perform full management operations without authentication.

**Verified attack chain (all steps confirmed from inside a default container):**

1. **MCP handshake** — `initialize` succeeds, returns session ID
2. **Enumerate management tools** — `tools/list` reveals: `list_servers`, `run_server`, `stop_server`, `remove_server`, `list_secrets`, `set_secret`, `delete_secret`, `get_server_logs`, `search_registry`
3. **List all running MCP servers** — names, status, proxy URLs, and ports of every server
4. **Query secrets store** — `list_secrets` returns secret names (values are encrypted, but access confirmation alone is concerning)
5. **Search registry** — enumerate available MCP server images and their tool capabilities
6. **Read server logs** — full MCP protocol traffic logs from any running server
7. **Pivot to other MCP servers** — using discovered proxy URLs, connect to any other running MCP server and call its tools
8. **Exfiltrate data** — outbound HTTP to attacker-controlled endpoints confirmed

**Impact:** A compromised or malicious MCP server can:
- Spawn new MCP servers with attacker-controlled images (`run_server`)
- Stop or remove legitimate servers (`stop_server`, `remove_server`)
- Pivot to a filesystem server and read/write files it was never authorized to access
- Pivot to native MCP servers (Desktop Commander, terminal servers) that have full host command execution
- Exfiltrate all discovered data to external endpoints

**PoC:** A complete Python PoC using only stdlib (`urllib.request`) was developed and successfully tested. See `toolhive_exploit_poc.py`.

**Root causes:**
1. Docker's `host.docker.internal` DNS resolves to the host from inside containers
2. Default container network (`toolhive-external`) has `Internal: false`
3. ToolHive MCP API on port 50444 has no authentication
4. MCP proxy endpoints for individual servers have no authentication

---

### Finding 2: Permission Profiles Are Cosmetic Without --isolate-network — HIGH

**Classification: DEFAULT BEHAVIOR**

The ToolHive permission profile system creates a false sense of security. The profile stored in the runconfig (`"outbound": {}` vs `"insecure_allow_all": true`) does not affect the actual Docker network configuration.

**Evidence from three-way test:**

| Profile | Runconfig Value | Docker Network | Actual Isolation |
|---------|----------------|----------------|-----------------|
| Default (registry) | `"network": {"outbound": {}}` | `toolhive-external` (Internal: false) | **None** |
| Explicit `network` | `"network": {"outbound": {"insecure_allow_all": true}}` | `toolhive-external` (Internal: false) | **None** |
| `--isolate-network` | `"network": {"outbound": {}}` | `toolhive-*-internal` (Internal: true) | **Full** |

Both the default empty profile and the explicit `insecure_allow_all` profile place the container on the same `toolhive-external` bridge network. The permission profile appears to be a policy intent marker that is not enforced at the Docker network level.

**Note on registry-specific profiles:** Some registry entries define host-restricted profiles (e.g., GitHub server restricts to `.github.com`, `.githubusercontent.com`). However, without enforcement at the Docker network/firewall level, these restrictions may also be cosmetic. This was not conclusively tested — the `github` server was not started to verify whether its DNS restrictions are enforced. This should be verified independently.

**Recommendation:** The `--isolate-network` flag should default to `true`, or at minimum the default Docker network should be `Internal: true` with explicit allowlisting for servers that need egress.

---

### Finding 3: Default Container Images Are Not Hardened — HIGH

**Classification: DEFAULT BEHAVIOR**

The default MCP server images (e.g., `docker.io/mcp/filesystem:latest`) are standard Node.js Alpine images that are not hardened for a security-sensitive workload. Verified against the running `filesystem` container:

| Property | Value | Hardened Expectation |
|----------|-------|---------------------|
| **User** | `root` (uid=0) | Non-root user |
| **Base OS** | Alpine Linux 3.22 | Distroless or scratch |
| **Available binaries** | 330 (wget, nc, nslookup, traceroute, vi, find, strings, etc.) | Minimal — only the MCP server binary |
| **Package manager** | `apk` — functional, can install packages at runtime | Removed or disabled |
| **npm** | Available — can install arbitrary Node.js packages | Removed |
| **Filesystem** | Writable (`ReadonlyRootfs: false`) | Read-only |
| **Node.js** | v22.16.0 full runtime | Minimal runtime |

**Live test:** Running `apk add --no-cache curl` from inside the container successfully downloaded and installed curl and 9 dependencies from Alpine repositories — confirming the container can self-arm with additional attack tools at runtime.

**Attacker impact:** Combined with Finding 1 (network access to host), an attacker who achieves code execution in any MCP server container can:
- Install any tool they need (`apk add python3 nmap openssh`)
- Run as root inside the container (maximizing container escape potential)
- Write persistent backdoors anywhere in the writable filesystem
- Use pre-installed `wget` and `nc` (netcat) for data exfiltration and reverse shells

**Positive mitigations already in place:**
- All Linux capabilities are dropped (`CapDrop: ALL` — all capability fields are `0x0000000000000000`)
- Seccomp filter is active (`Seccomp: 2` with 1 filter)
- Only 18 Alpine packages in the base image (relatively minimal)

**Recommendation:**
- Use distroless or scratch-based images with only the MCP server binary
- Run as a non-root user (add `USER nonroot` to Dockerfile)
- Set `ReadonlyRootfs: true` in the container config
- Remove `apk`, `npm`, and other package managers from the image
- Strip unnecessary binaries (especially `wget`, `nc`, `nslookup`, `traceroute`)

---

### Finding 4: Unbounded Log File Growth — MEDIUM

**Classification: DEFAULT BEHAVIOR**

MCP server log files grow without rotation or size caps. Observed on the assessed system:

- `playwright.log`: 277 MB
- `filesystem.log`: 176 MB
- `everything.log`: 115 MB
- Total log directory: >1 GB

These logs contain full MCP protocol traffic including file paths, query content, and tool call parameters. There is no apparent log rotation mechanism.

**Recommendation:** Implement log rotation with configurable size limits. Audit log contents for sensitive data (credentials, PII, file contents passed through MCP tools).

---

### Finding 5: Kubeconfig Mounted into MCP Container — MEDIUM

**Classification: NON-DEFAULT (user configuration)**

The `k8s.json` runconfig on the assessed system mounts the user's full kubeconfig file (`~/.kube/config`) into the container. This is a consequence of how the K8s MCP server is designed (it needs cluster credentials), but combined with the default outbound network access (Finding 2), the container has unrestricted access to every Kubernetes cluster defined in the kubeconfig.

**Verification:** This mount is created when the user runs `thv run k8s` — it is part of the K8s server's registry configuration, not a user override. However, using the K8s server at all is a user choice, making this a known-risk configuration rather than a universal default.

**Recommendation:** Create a dedicated kubeconfig with limited RBAC permissions. Use `--isolate-network` to restrict the K8s container's network access to only the cluster API server endpoints.

---

### Finding 6: Telemetry Enabled by Default — MEDIUM

**Classification: DEFAULT BEHAVIOR**

The configuration file `config.json` shows `"isTelemetryEnabled": true`. A Sentry error-reporting directory is also present. While anonymous usage metrics are common, the user is not prominently informed at first launch.

**Recommendation:** Run `thv config usage-metrics disable` if telemetry is not desired.

---

### Finding 7: Local API Server Unauthenticated — LOW

**Classification: DEFAULT BEHAVIOR**

The `thv serve` API (port 50033) and experimental MCP endpoint (port 50444) accept unauthenticated requests. While both are bound to localhost, any local process can interact with them. This is directly exploited by Finding 1 (containers reaching the API via `host.docker.internal`).

On a personal workstation with no malicious local processes, the risk from local-only access is low. The risk becomes critical when combined with Docker's `host.docker.internal` DNS (Finding 1).

**Note:** ToolHive does support OIDC authentication for incoming MCP proxy requests, but this is not enabled by default and does not cover the management API itself.

---

### Finding 8: Run Config Directory Permissions — LOW

**Classification: DEFAULT BEHAVIOR**

Run config files are correctly set to `-rw-------` (owner-only). The secrets file uses AES-256-GCM encryption with the OS keyring. However, parent directories (`runconfigs/`, `statuses/`) are `drwxr-x---` (group-readable), allowing group members on a multi-user system to enumerate which MCP servers are configured.

**Recommendation:** Tighten directory permissions to `drwx------` (700).

---

### Finding 9: Sentry Error Reporting Integration — LOW

**Classification: DEFAULT BEHAVIOR**

A `sentry/` directory is present in the application data folder. Sentry crash reports can inadvertently include stack traces, environment variables, and file paths.

**Recommendation:** Review Stacklok's privacy policy. Disable if operating in a sensitive environment.

---

## 4. Corrected Finding: insecure_allow_all as Default

**Classification: PARTIALLY CORRECTED from original review**

The original review stated that all 11 run configurations used `insecure_allow_all: true`. Upon verification:

- The **registry default** for `filesystem` produces `"outbound": {}` (empty), NOT `insecure_allow_all: true`
- The `insecure_allow_all: true` entries in the user's existing configs were from previous explicit `--permission-profile network` usage or from an older ToolHive version
- Some registry entries (like `fetch`) DO ship with `insecure_allow_all: true` because they need internet access
- The `github` registry entry ships with restricted host rules (`.github.com`, `.githubusercontent.com`)

**However, this correction is moot** because as Finding 2 demonstrates, the difference between `"outbound": {}` and `"insecure_allow_all": true` is cosmetic — both result in identical Docker network placement with full outbound access. The real issue is the Docker network configuration, not the permission profile string.

---

## 5. Items Verified as Non-Existing

### CVE-2025-47274 Active Exploitation — NOT FOUND

CVE-2025-47274 (plaintext secrets in runconfig files) was patched in version 0.0.33. No plaintext secrets were found in any current runconfig file on the assessed system. The encrypted secrets store uses AES-256-GCM with macOS keyring integration.

**Status:** Patched. No residual plaintext secrets detected. Users who ran versions prior to 0.0.33 should still rotate secrets as a precaution.

---

## 6. Positive Security Observations

These remain valid from the original assessment:

- **Container isolation by default:** MCP servers run in Docker containers with namespace and filesystem isolation — a meaningful improvement over native process execution.
- **Encrypted secrets store:** AES-256-GCM encryption backed by the macOS keyring. Multiple providers supported (encrypted, 1Password, environment).
- **Localhost-only binding:** Both the API server and MCP proxy bind exclusively to 127.0.0.1.
- **Proper code signing:** Full Apple Developer ID certificate chain with hardened runtime and stapled notarization.
- **Permission profile infrastructure:** The RunConfig system exists and supports fine-grained profiles — it needs enforcement, not redesign.
- **OIDC/OAuth support:** Enterprise authentication infrastructure exists for proxy access control.
- **Registry-level profile curation:** The registry does define per-server profiles (e.g., GitHub restricted to `.github.com`). This shows security intent that could be made effective with network-level enforcement.
- **--isolate-network flag exists:** The mechanism for true isolation exists and works correctly. It just needs to be the default.

---

## 7. Recommendations Summary

| Priority | Finding | Classification | Action | Effort |
|----------|---------|----------------|--------|--------|
| **CRITICAL** | #1 Lateral movement via host.docker.internal | DEFAULT | Block `host.docker.internal` and Docker gateway IPs by default; add auth to MCP API | Medium |
| **HIGH** | #2 Permission profiles not enforced | DEFAULT | Make `--isolate-network` the default; enforce profile rules at network/firewall level | Medium |
| **HIGH** | #3 Unhardened container images | DEFAULT | Use distroless images; non-root user; read-only FS; remove package managers and unnecessary binaries | Medium |
| **MEDIUM** | #4 Unbounded log growth | DEFAULT | Implement log rotation; audit logs for sensitive data | Low |
| **MEDIUM** | #5 Kubeconfig exposure | NON-DEFAULT | Document risk; recommend limited-RBAC kubeconfig | Low |
| **MEDIUM** | #6 Telemetry default | DEFAULT | Prominent first-launch opt-in; `thv config usage-metrics disable` | Low |
| **LOW** | #7 Unauthenticated local API | DEFAULT | Enable auth by default or restrict to loopback-only process verification | Medium |
| **LOW** | #8 Directory permissions | DEFAULT | Tighten to 700 | Trivial |
| **LOW** | #9 Sentry integration | DEFAULT | Document data collection; provide disable option | Low |

---

## 8. Attack Scenario: Full Chain Demonstration

The following attack was demonstrated end-to-end using only Python standard library from inside a default ToolHive container:

```
Container (filesystem)
    │
    ├──→ host.docker.internal:50444  (ToolHive MCP API)
    │       ├── initialize → session established (no auth)
    │       ├── tools/list → 9 management tools discovered
    │       ├── list_servers → all running servers + proxy URLs
    │       ├── list_secrets → secret names enumerated
    │       ├── search_registry → available server images
    │       └── get_server_logs → full MCP protocol logs
    │
    ├──→ host.docker.internal:<proxy_port>  (Other MCP server)
    │       ├── initialize → session established (no auth)
    │       ├── tools/list → target server tools enumerated
    │       └── tools/call → arbitrary tool execution
    │
    ├──→ host.docker.internal:6443  (Kubernetes API)
    │       └── /version → cluster version confirmed
    │
    ├──→ host.docker.internal:11434  (Ollama LLM API)
    │       └── /api/tags → model inventory enumerated
    │
    └──→ httpbin.org  (External exfiltration)
            └── POST → data successfully exfiltrated
```

**Key point:** This entire chain works from a container started with `thv run filesystem -- /tmp` — no flags, no configuration, no elevated privileges. The container only needs Python (or wget/curl) to execute the attack.

---

## 9. Conclusion

This revised assessment corrects the original review's classification of `insecure_allow_all` as user misconfiguration — the underlying network exposure is **default behavior** regardless of the permission profile setting.

ToolHive's architecture shows strong security intent: container isolation, encrypted secrets, permission profiles, OIDC support, and localhost-only binding are all evidence of a security-first design philosophy. The critical gap is between intent and enforcement: the permission profile system defines what *should* be restricted but doesn't enforce it at the Docker network level by default.

The `--isolate-network` flag demonstrates that the engineering team has already built the correct isolation mechanism. Making it the default — or making the default Docker network `Internal: true` — would address the most critical findings (1 and 2) with a relatively contained change.

For the broader MCP ecosystem, ToolHive's lateral movement exposure via `host.docker.internal` is a class of vulnerability that affects any container-based MCP orchestrator on Docker Desktop. The combination of unauthenticated MCP APIs, Docker's host DNS resolution, and containers sharing a non-internal bridge network creates an attack surface that transcends ToolHive specifically.

---

## Appendix A: Files Produced During This Assessment

| File | Description |
|------|-------------|
| `ToolHive_Security_Assessment.md` | Original review (superseded by this document) |
| `ToolHive_Security_Assessment_v2.md` | This verified review |
| `toolhive_exploit_poc.py` | Python PoC for lateral movement attack chain |
| `github_issue_draft.md` | GitHub issue: default permission profile |
| `github_issue_lateral_movement.md` | GitHub issue: lateral movement via host.docker.internal |
