---
name: shadow-sandbox
description: Review or change Shadow's Docker command runner, tool image, mounts, or target-network policy.
---

# Shadow sandbox

Read `docs/SAFETY.md` and `docs/ARCHITECTURE.md` for the relevant boundary. Trace the host-to-Docker path and inspect the actual container settings before changing them. Agent shell commands must never fall back to the host. Treat Docker socket access, bind mounts, DNS and redirects, resource limits, and output redaction as separate checks. Run the isolation integration test with a locally available Linux image after changing container behavior, and report whether Docker access was available.
