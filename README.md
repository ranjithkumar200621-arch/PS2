# PS2 · GOD VALLEY

Android-native scam and misinformation checker. Read [ARCHITECTURE.md](ARCHITECTURE.md) and [SPECIFICATION.md](SPECIFICATION.md) for scope and boundaries.

This is an installable test build, not a completed or security-audited product. No trained scam model is included and no model accuracy is claimed.

## Milestone status

### Implemented and tested

- Notification structured parsing: `MessagingStyle` messages are processed by timestamp and sender; plain notifications use `EXTRA_TEXT` before `TEXT_LINES`, never `EXTRA_BIG_TEXT` as a batch.
- Group summaries are skipped. Multiple unseen messages are analyzed independently and together by conversation/sender.
- A privacy-preserving in-memory-to-digest ledger tracks processed messages using salted SHA-256 digests only. Text is not persisted; the ledger is limited to 2000 entries and expires entries after 30 days.
- Monitoring rebase occurs on listener connect/disconnect and when monitoring or app selection is enabled. Reposted notifications and paused monitoring produce no warning.
- Harmless input displays “No suspicious signals detected” with an explicit statement that this does not prove safety.
- Manual-check results, reviewed queries, and server responses are cleared whenever shared or edited input changes.
- Historical Room findings store verdict and reasons only, with seven-day retention and history deletion.
- Android debug APK build succeeds; 17 Kotlin/JUnit detector and notification-ledger tests pass; APK v2 signing verifies.
- Backend suite passes 5 tests in a Python virtual environment.

### Implemented but untested on real devices

- NotificationListenerService coverage across Android 16 and other supported Android versions.
- Battery use, notification-update behavior, real-device permissions, shared-image OCR, QR decoding, and Compose UI.
- Existing backend provider integrations and Android per-request consent flow.

### Unavailable because credentials or infrastructure are missing

- Hosted production backend, provider credentials, and production HTTPS deployment.
- RDAP, official government-source, Gemini, PostgreSQL, and signed threat-update infrastructure are not configured.

### Not yet implemented

- Validated pretrained ONNX multilingual scam model and exact tokenizer integration.
- Tamil image OCR and user-initiated camera QR scanning.
- RDAP context, isolated redirect inspection, claim-date/eligibility matching, grounded Gemini explanations.
- Signed, versioned threat updates with rollback protection.
- Production signing key, release APK, Play Store process, and real-device release evidence.

## Android build

Requirements: JDK 17, Android SDK 35, and Gradle 8.11.1.

```bash
cd android
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

The replacement test APK is `android/app/build/outputs/apk/debug/app-debug.apk` (73 MB). It is V2-signed with the Android debug certificate and is not a production-signed release.

SHA-256: `05b4c141f651330f85ba432012299587c398387305ab7e4d54313930ff795f9`

Install only after confirming upgrade compatibility with the existing debug package. A release APK requires a separately secured signing key outside this repository.

Select messaging apps, enable monitoring, grant notification access and warning notification permission. Send a controlled test notification from a selected messenger containing a fake urgent KYC request and an example.com link. Do not use real banking credentials. Open PS2 for reasons. Local history refreshes when the activity reopens. Pause disables new screening. Delete clears local warning records.

## Backend

Python 3.11+ is recommended. From the repository root:

```bash
python -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
cd backend
../.venv/bin/python -m unittest -v
```

Set `PS2_API_TOKEN` and optional provider credentials as server environment variables only. Put the FastAPI service behind authenticated HTTPS with size and rate limits. Do not expose development HTTP directly or place credentials in the APK.

## Release targets, not achievements

- Scam recall ≥95%
- False-positive rate ≤2%
- Local inference under 500 ms
- Online verification p95 under 10 seconds
- Zero unauthorized raw-notification uploads

These targets require independent labeled evaluation and real-device testing. No percentage or latency result is claimed unless it is measured and documented.

## References

- https://developer.android.com/reference/android/service/notification/NotificationListenerService
- https://developer.android.com/develop/ui/compose/bom
- https://developers.google.com/ml-kit/vision/text-recognition/v2
- https://docs.cloud.google.com/web-risk/docs/lookup-api
- https://developers.google.com/fact-check/tools/api/reference/rest/v1alpha1/claims/search