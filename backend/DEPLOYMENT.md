# Verification service deployment

The Dockerfile is prepared but has not been built or deployed in this session. Deploy this directory to a container host supporting HTTPS. Port: 8000. Health path: /health. Use one process initially. Configure provider keys only in the host's secret settings.

Required secret: PS2_API_TOKEN, a long randomly generated value. Optional secrets: WEB_RISK_API_KEY and FACT_CHECK_API_KEY. Without provider keys, RDAP still supplies domain metadata, but reputation and fact checks remain unavailable. No missing provider is treated as a safe result.

The host must terminate HTTPS, cap request bodies (16 KiB is sufficient), limit requests per user and redact sensitive request/response data from logs. The development shared token is suitable for a private demo only. Public distribution needs individual revocable credentials. The application does not contain provider keys.

On the phone, Check → Connection settings: enter the HTTPS endpoint and the private demo token. Review each query and consent before sending. Do not include personal message content when checking a factual claim. Verify controls with non-sensitive examples before use.

The RDAP bootstrap snapshot is sourced from https://data.iana.org/rdap/dns.json and contains registry service URLs, not a threat list. Refresh it from IANA and rerun backend tests when updating the deployment. Registry data does not establish website trust.

Not provided by this deployment: Gemini explanations, a government-claim corpus, PostgreSQL intelligence management, isolated redirect inspection or a validated regional classifier. These remain separate implementation work.
