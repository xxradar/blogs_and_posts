# Your MCP Servers Are Running. But Are They Actually Isolated?

## Why platform teams need to treat AI tool infrastructure with the same rigor as production workloads

*Philippe Bogaerts*

---

The Model Context Protocol is everywhere. In the span of a year, MCP has gone from a niche Anthropic specification to the connective tissue between AI assistants and the tools they operate: file systems, databases, APIs, Kubernetes clusters, CI pipelines, and everything in between. For platform engineers, MCP servers are rapidly becoming the newest class of infrastructure to manage, secure, and scale.

And most teams are not ready for what that means.

If you've been following the MCP ecosystem, you've likely noticed the pattern: developers spin up MCP servers the way they used to spin up npm packages. Quickly, enthusiastically, and with very little scrutiny of what's actually happening under the hood. The MCP registry is growing fast. New servers appear weekly. The tooling to orchestrate them is maturing. But the security posture of the average MCP deployment? It lags behind in ways that should concern any platform team.

I've spent the last several months conducting independent security assessments of MCP server infrastructure, looking at how these servers are deployed, how they communicate, what they can reach, and what happens when one of them misbehaves. What I've found isn't a story about any single product failing. It's a story about an ecosystem that hasn't yet internalized a fundamental lesson from the last decade of platform engineering: **isolation is not a feature you bolt on. It's an architectural decision you make from day one.**

## The container illusion

The good news is that the MCP ecosystem has largely moved past running servers as native processes on the host. The leading orchestration tools now deploy MCP servers inside containers (Docker or Podman), which gives you namespace isolation, filesystem boundaries, and the general comfort of knowing your AI tool server isn't running as a bare process with your user permissions.

The less good news is that "runs in a container" and "is actually isolated" are very different statements.

Through systematic testing of default container configurations across several MCP orchestration platforms and registry server images, a consistent pattern emerges: containers are placed on Docker bridge networks with full outbound access. They can reach the internet. They can reach the host machine. They can often reach each other. The permission systems that are supposed to restrict this access (profiles, policies, allowlists) frequently exist as metadata that isn't enforced at the network level.

Think about what this means in practice. You deploy a filesystem MCP server that should only have access to `/tmp/project`. You deploy a GitHub MCP server that should only talk to `api.github.com`. You deploy a database MCP server with credentials for your staging environment. All three land on the same Docker bridge network. All three can reach the host. All three can reach the internet. And if any one of them is compromised (through a supply chain attack on its base image, a vulnerability in the MCP protocol handling, or a malicious tool definition), it can pivot to everything the others can reach.

This is not a theoretical concern. In assessments I've conducted against default configurations, I've demonstrated lateral movement from a single container with minimal declared permissions to full visibility and control over the host's MCP infrastructure, without any authentication required at any step. The attack surface isn't the container escape everyone worries about. It's the network path that was left open by default.

## The permission profile gap

Most MCP orchestration tools have some concept of permission profiles. You can declare that a server needs network access, or filesystem access, or should run in a restricted mode. These profiles are a good idea. They signal intent and they create a framework for enforcement.

The problem is the gap between declaration and enforcement.

In assessments across multiple orchestration tools and their default configurations, I've found that permission profiles are often stored as configuration metadata but not translated into actual Docker network rules, firewall policies, or seccomp restrictions. A profile that says "no outbound network access" and a profile that says "full network access" result in identical container configurations: same Docker network, same bridge, same unrestricted egress.

This creates a dangerous false sense of security. Platform teams configure their MCP servers with restrictive profiles, see the configuration stored correctly, and assume the restriction is in effect. The audit trail looks clean. The runtime reality is wide open.

For platform engineers, this should ring familiar. We've seen this pattern before: with Kubernetes NetworkPolicies that aren't enforced because no CNI plugin is configured, with RBAC rules that exist in manifests but aren't applied, with security groups that look restrictive in the console but have implicit allow-all rules. The lesson is always the same: **policy without enforcement is documentation, not security.**

## Why microsegmentation matters here

The word "microsegmentation" has been overused in enterprise security marketing, but the core principle is exactly right for MCP infrastructure: each workload should only be able to communicate with the specific endpoints it needs, and nothing else.

For MCP servers, this means:

A filesystem server should reach the mounted directory and nothing else. Not the internet. Not the host. Not other containers. Not the MCP management API.

A GitHub server should reach `api.github.com` and `*.githubusercontent.com`. Not your internal Kubernetes API. Not your database. Not the filesystem server running next to it.

A database server should reach your database endpoint on a specific port. Not the internet. Not the host's Docker socket. Not the MCP orchestrator's control plane.

This is the same principle platform teams apply to production microservices, and MCP servers deserve the same treatment. They handle credentials. They access sensitive systems. They execute tool calls that can read files, modify infrastructure, and exfiltrate data. The fact that they're "just AI tools" doesn't make them less dangerous. If anything, the combination of broad tool access and an AI agent that can be prompted to take unexpected actions makes them *more* dangerous than a typical microservice.

Consider the blast radius difference. A compromised microservice typically has access to one database, one downstream API, maybe a message queue. A compromised MCP server, especially one running on an unrestricted network alongside other MCP servers, potentially has access to every system those other servers are connected to. A filesystem server becomes a path to your source code. A Kubernetes server becomes a path to your clusters. A database server becomes a path to your production data. The lateral movement isn't container-to-container in the traditional sense. It's tool-to-tool, mediated by the MCP protocol itself, and it follows whatever trust boundaries the orchestrator has (or hasn't) enforced.

This is why microsegmentation for MCP infrastructure isn't optional hardening. It is the architectural prerequisite for running multiple MCP servers on the same host without accepting that a compromise of any one of them is a compromise of all of them.

The mechanism for this isolation already exists in most container runtimes. Docker supports internal networks that block all outbound traffic by default. Podman has similar capabilities. Kubernetes NetworkPolicies, when enforced by a proper CNI plugin, can restrict pod-to-pod and pod-to-external communication with precision. The tooling is there. What's missing is the default.

## Container hardening: the forgotten layer

Network isolation is the most critical gap, but it's not the only one. The container images used by most MCP servers are surprisingly permissive for infrastructure that handles sensitive tool operations.

In assessments of default MCP server images, I've consistently found containers running as root, using full Alpine or Debian base images with hundreds of available binaries, with writable filesystems, and with functional package managers that can install additional tools at runtime. From inside a default MCP server container, you can typically run `apk add curl nmap python3` and arm the container with whatever you need for further exploitation.

This matters because container compromise is a when, not an if. Supply chain attacks on npm packages (which many MCP servers depend on) are a regular occurrence. MCP protocol parsing vulnerabilities will be found. It is a young protocol. When a container is compromised, the question isn't whether the attacker gets in. It's what they can do once they're there.

Hardened containers (distroless base images, non-root users, read-only filesystems, stripped binaries, no package managers) dramatically reduce the blast radius. They don't prevent compromise, but they make post-exploitation significantly harder. This is defense in depth, and it's table stakes for production infrastructure.

## The host.docker.internal problem

There's a specific architectural pattern in MCP infrastructure that deserves attention from platform teams: the relationship between containers and the host's MCP management API.

Most MCP orchestrators run a control plane on the host that manages server lifecycle: starting, stopping, configuring, and monitoring MCP servers. This control plane typically listens on localhost, which sounds safe. But containers can reach the host machine through DNS entries that resolve to the host's IP, and this works across virtually every container runtime in use today.

On Docker Desktop (macOS, Windows, and Linux), the `host.docker.internal` hostname is automatically injected into every container and resolves to the host. On Docker Engine running natively on Linux (without Docker Desktop), the same hostname is available when containers are started with `--add-host=host.docker.internal:host-gateway`, which many orchestration tools add by default. Even without that flag, containers on default bridge networks can typically reach the host through the Docker gateway IP (often `172.17.0.1`). Podman takes it a step further: since version 5.x, it injects both `host.containers.internal` and `host.docker.internal` into every container's `/etc/hosts` automatically, no flags required.

In short, this is not a Docker Desktop quirk. It is a cross-platform reality. On every major container runtime, containers can reach the host by default unless explicitly placed on an internal network.

If the management API does not require authentication (and in most current implementations it does not), any container can reach it and perform full management operations: enumerate all running servers, read their logs, start new servers, stop existing ones, and pivot to any other server's proxy endpoint.

This is the lateral movement pattern that transforms a single container compromise into full infrastructure compromise. And it works with default settings, default images, and default network configurations. No special privileges required.

For platform teams evaluating MCP infrastructure, this is the single most important thing to test: **from inside a container, what can you reach on the host?** If the answer is "the MCP management API, unauthenticated," you have a critical exposure regardless of what your permission profiles say.

## An evaluation framework for platform teams

Based on independent security assessments across the MCP ecosystem, here's a practical framework for evaluating MCP server platforms. These aren't aspirational goals. They are the minimum bar for running MCP servers in any environment that handles real data.

### Network isolation

- **Default network posture:** Are containers placed on Docker-internal networks by default, or do they get full outbound access? The default matters more than the option.
- **Host reachability:** Can containers reach `host.docker.internal` or the Docker gateway IP? Can they reach the MCP management API?
- **Per-server network policy:** Can you define which specific endpoints each MCP server is allowed to reach? Is this enforced at the network/firewall level, or just stored as metadata?
- **Inter-container isolation:** Can one MCP server reach another MCP server's proxy endpoint? If so, is this authenticated?

### Authentication and authorization

- **Management API authentication:** Does the control plane API require authentication? What about from localhost? What about from `host.docker.internal`?
- **MCP proxy authentication:** Are individual server proxy endpoints authenticated? Can any process that can reach the port call tools?
- **OIDC/OAuth integration:** Is enterprise SSO available for MCP proxy access? Is it enabled by default?
- **Per-tool authorization:** Can you restrict which tools are available to which clients, not just which servers?

### Container hardening

- **Base image:** Distroless/scratch, minimal Alpine, or full OS? How many binaries are available?
- **Runtime user:** Root or non-root?
- **Filesystem:** Read-only root filesystem, or writable?
- **Package managers:** Can the container install additional software at runtime?
- **Capabilities:** Are all Linux capabilities dropped? Is seccomp active?
- **Image provenance:** Are images signed? Is there a software bill of materials?

### Secrets management

- **Storage:** Are secrets encrypted at rest? What encryption scheme?
- **Key management:** Where is the encryption key stored? OS keyring, file, environment variable?
- **Exposure:** Are secrets ever written to log files, runconfigs, or environment variables in plaintext?
- **Rotation:** Can secrets be rotated without restarting servers?

### Operational security

- **Logging:** Are MCP protocol logs bounded? Is there log rotation? Do logs contain sensitive data (file contents, credentials, PII)?
- **Telemetry:** Is telemetry enabled by default? What data is collected? Can it be disabled?
- **Update mechanism:** How are MCP server images updated? Is there vulnerability scanning?

### Policy enforcement verification

This is the most important category in the framework, and the one most teams skip. It answers the question: does your security configuration actually do what it claims?

- **Test methodology:** Deploy two servers with different permission profiles, one permissive and one restrictive. From inside each container, attempt to reach the same set of endpoints. Do the profiles produce different actual behavior, or just different configuration metadata? If both containers can reach the same endpoints, your profiles are cosmetic.
- **The bridge test:** Inspect the Docker networks both containers are attached to. Are they on the same bridge? Is the bridge `Internal: true` or `Internal: false`? Run `docker network inspect` on every network your MCP containers use. If you see `"Internal": false`, your containers have outbound internet access regardless of what their permission profile says.
- **The host test:** From inside each container, attempt to reach `host.docker.internal` on the MCP management port. Does the "restricted" container behave differently from the "unrestricted" one? If both can reach the management API, your network isolation isn't working.
- **The pivot test:** From inside one MCP server container, attempt to connect to another MCP server's proxy endpoint and call its tools. If this succeeds without authentication, any compromised server can control every other server.

A three-way comparison test works well here: run the same server image with default settings, with an explicit network-access profile, and with full network isolation enabled. Compare the actual Docker network assignment, the reachable endpoints, and the container's effective capabilities across all three. The results will tell you whether your platform's security model is enforcement or aspiration.

## What platform teams should do now

If your organization is deploying MCP servers (and if your developers are using AI coding assistants, you almost certainly are), here is the immediate action plan:

**Audit your current state.** Find out what MCP servers are running, what network they're on, and what they can reach. Most teams are surprised by the answer.

**Test your isolation claims.** Don't trust permission profiles at face value. Get inside a container and try to reach the host, the internet, and other containers. Document what actually works versus what the configuration says should work.

**Enable network isolation.** If your orchestration tool has an isolation flag, enable it. If it doesn't, create Docker-internal networks manually and assign MCP server containers to them. Allowlist only the specific endpoints each server needs.

**Harden your images.** If you're running the default registry images, evaluate switching to hardened alternatives. At minimum, run as non-root and set the filesystem to read-only.

**Authenticate your APIs.** If your MCP management API is unauthenticated, treat it as a priority fix. Localhost-only binding is not sufficient when containers can reach the host.

**Treat MCP servers as production infrastructure.** Apply the same standards you apply to your microservices: network policies, RBAC, image scanning, log management, secrets rotation. The fact that they're "AI tools" doesn't make them less critical. It makes them more so, because they're designed to take actions on behalf of humans with broad system access.

**Build it into your Internal Developer Platform.** If your organization has an IDP, MCP server deployment should be a paved road, not a side path. Define golden paths for MCP server deployment that include network isolation, hardened images, and authenticated APIs by default. Make the secure configuration the easy configuration. If developers have to opt in to security, most won't, not out of negligence, but because they're focused on making their AI tooling work, not on Docker network internals.

## The bigger picture

The MCP ecosystem is doing many things right. Container-based deployment is the correct architecture. Permission profiles are the right abstraction. Encrypted secrets stores, OIDC support, and registry-level security metadata all show that the ecosystem's builders are thinking about security.

What's missing is the last mile: translating security intent into security enforcement. The profiles need to become firewall rules. The isolation flags need to become defaults. The container images need to be hardened for the threat model they actually face.

This is, fundamentally, a platform engineering problem. It's about building the right defaults, the right abstractions, and the right guardrails so that developers can use MCP servers without needing to be security experts. That's what platforms do: they encode organizational standards into infrastructure so that the safe path and the easy path are the same path.

The MCP ecosystem will get there. The intent is clear, the architecture is sound, and the building blocks exist. But right now, in February 2026, the defaults are wrong. And platform teams are the ones who need to fix them, not by avoiding MCP servers, but by treating them with the engineering rigor they deserve.

---

*Philippe Bogaerts is an independent security researcher who conducts architecture and security assessments of AI infrastructure and developer tooling.*
