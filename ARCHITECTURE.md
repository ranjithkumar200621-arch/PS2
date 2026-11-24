## Version 0.2 update

Warnings now identify the source app, sender and exact message. Each alert opens its own record. Flagged text and sender information are encrypted with Android Keystore and retained locally for seven days, with deletion and local false-positive feedback. History migrates from version 0.1. Structured notification messages are processed individually with persistent duplicate fingerprints; expanded history is not concatenated. Fallback notifications without structured messages have reduced coverage.

Broad keyword counting has been replaced by contextual fraud patterns. A licensed OTIS English spam model is bundled via ONNX with matching WordPiece tokenization. Evaluation found severe false positives (including “hi”), so **its scores cannot trigger warnings or change verdicts**. Context rules determine alerts. See MODEL_CARD.txt and model-validation.json. These are synthetic development checks, not a representative accuracy benchmark. Tamil/Tanglish remain rule-based. No production accuracy target is claimed.

Build, Android lint and 22 local tests passed. Five Android 15 emulator tests cover encryption, model loading, structured notifications, record identity/deduplication and database migration. Physical Android 16 testing is still needed. Online verification still requires a hosted backend and provider credentials. Remaining advanced scope is not complete.

The following older design/prototype notes describe the initial version; this update supersedes conflicting implementation status.

# PS2 architecture

Source of scope: GOD_VALLEY_PS2.md. Native Android only.

```mermaid
flowchart TD
  N[Consented notification previews] --> L[Local normalization and rules]
  S[Shared text or image] --> O[On-device OCR and QR decoding]
  O --> L
  L --> R[Risk result and safety advice]
  L --> D[Room: reasons only, no raw messages]
  U[User reviews redacted query and consents] --> B[FastAPI verification]
  B --> W[Web Risk URL reputation]
  B --> F[Fact Check retrieval]
  W --> R
  F --> R
```

## Boundaries
No chat history, SMS database permissions, accessibility scraping, screen capture, transaction interception or VPN. Notification contents remain local. Cloud checks require a separate preview and approval for each query. URLs lose query/fragment/userinfo before verification. Never visit submitted URLs in the API process. Redirect inspection needs an isolated egress-restricted worker and remains disabled. Source text and API content are untrusted.

## Compact implementation
- MainActivity.kt: Compose onboarding, app selection, pause, sharing, query consent, result display.
- Detection.kt: local rules, QR intent, redaction and bounded parsing.
- Protection.kt: notification listener, Room reason history, WorkManager retention.
- backend/main.py: authenticated, bounded external verification, no request persistence.

## Model release gate
Rules are a baseline, not a pretrained model. No arbitrary unvalidated weights are bundled. Benchmark XLM-R or a lighter multilingual classifier against the baseline on independent Tamil, Tanglish and English campaign/time splits. Export selected model plus its exact tokenizer to ONNX. Require tested input/output schema, model license, calibrated thresholds and device latency/memory evidence before enabling inference. An absent model must remain visible in the UI.

## Remaining integrations
Gemini Flash must only explain retrieved evidence, never create verdicts. PostgreSQL is reserved for curated threat intelligence, not raw notifications. RDAP is a weak domain signal, not fraud proof. Threat update signatures, isolated redirects, validated ONNX inference and grounded Gemini are release gates, not implemented claims.

## Evaluation
Targets only: recall >=95%, false positive rate <=2%, local inference <500ms, online p95 <10s, unauthorized raw uploads zero. Measure notification coverage, battery and language-specific quality separately. No achieved metrics claimed.
