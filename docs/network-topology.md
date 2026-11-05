# Compose network topology

`lab_net` is the target segment (`172.30.0.0/24`) and is declared `internal: true`. Juice Shop (`172.30.0.10`), DVWA (`172.30.0.20`), ZAP (`172.30.0.30`), scanner-runner (`172.30.0.40`), and backend (`172.30.0.50`) are attached. Targets, ZAP, and the runner have no other network and no published host port. The runner's scan endpoints also require the caller IP to equal the fixed backend address (`172.30.0.50`) as well as a bearer token; the frontend is not on `lab_net`. Runner accepts only literal IPv4 targets inside the configured CIDR and revalidates them just before command execution.

`app_net` is also internal and connects only frontend and backend. It publishes no network route for the frontend beyond the explicit host mapping `3000:3000`; backend port 8000 is only exposed to Compose peers.

`egress_net` is a normal bridge and its only member is backend, reserved for the future LLM API adapter. The present backend has no outbound LLM client. Compose membership is not a destination allowlist: Docker's default bridge does not restrict backend traffic to a provider domain. Before adding any LLM request path, enforce approved provider-specific egress at the host/network boundary. This caveat is explicit rather than claiming network-level filtering that Compose does not supply.

Optional Metasploitable2 is not included because Prompt 1 notes it has no official image. No dev-only host-published target override is included.

Nikto remains non-executable in this scaffold, even if `ENABLE_ACTIVE_VALIDATION=true`: the runner audits and rejects the request until a later milestone supplies a real recorded human-approval workflow. A caller-provided approval reference alone is not treated as approval.
