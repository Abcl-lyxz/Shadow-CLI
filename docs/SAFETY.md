# Target and PoC policy

Natural-language instructions may identify a target. The default authorized scope is its exact URL origin (scheme, host, port). Subdomains, sibling domains, resolved IPs outside that origin, and third-party redirects are excluded unless the user explicitly adds them. Scope is displayed in the TUI and applies to all agents.

The intended product policy allows read operations and bounded test writes, such as creating a dedicated test account or a clearly named marker that can be removed. Test writes require evidence of the intended target, an audit record, and cleanup. RCE execution, destructive modification or deletion of real data, denial of service, and actions whose effects cannot be bounded or rolled back are prohibited. A suspected issue that needs a prohibited action stays unverified, with a proposed manual validation plan.

Do not infer safety from HTTP methods alone: GET can mutate state, and POST can be a login. The runtime must classify side effects and mediate network access. Until that enforcement exists, live network requests and test writes are disabled for model-generated tools. This is an implementation gate, not a prompt rule.

Keep API keys in the OS keyring and never mount them into tool containers. Minimize and redact evidence containing personal data and secrets. A report must distinguish confirmed observations from hypotheses.
