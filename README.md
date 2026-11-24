# PS2 · GOD VALLEY

Architecture first: read [ARCHITECTURE.md](ARCHITECTURE.md). The original project scope is in [SPECIFICATION.md](SPECIFICATION.md). This is an installable Android test build, not the complete or security-audited product. The previously delivered signed debug APK is separate from this source repository. Build an APK using the instructions below. No model accuracy is claimed.

## Android build
Use Android Studio with JDK 17, Android SDK 35 and Gradle 8.11.1. Open `android/` as the project. A Gradle 8.11.1 wrapper is included. Run `./gradlew :app:assembleDebug`. Debug APK: `app/build/outputs/apk/debug/app-debug.apk`. Install through Android Studio on a USB-debugging-enabled phone. A release APK requires your own signing key, kept outside this project.

Select messaging apps, enable monitoring, grant notification access and warning notification permission. Send a controlled test notification from a selected messenger containing a fake urgent KYC request and an example.com link. Do not use real banking credentials. Open PS2 for reasons. Local history refreshes when the activity reopens. Pause disables new screening. Delete clears local warning records.

## Backend
Python 3.11+. Create a virtual environment, install `backend/requirements.txt`, set PS2_API_TOKEN to a strong random secret and optionally WEB_RISK_API_KEY and FACT_CHECK_API_KEY. Run `uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log`. Put an authenticated HTTPS reverse proxy in front for phone access. Configure proxy request-size/rate limits, timeouts and log redaction. Never expose development HTTP directly to the phone or put provider keys in the APK. The app holds the backend token only in memory. Use individual short-lived credentials before public release.

Run backend tests from backend/ with `python -m unittest -v`.

## Implemented in source
Consent onboarding, app selection, pause, local English/Tamil/Tanglish keyword baseline, deduplicated warnings, Room reason-only history with periodic deletion, Android sharing, Latin OCR, QR decoding, UPI intent explanation, reviewed per-request cloud consent, Web Risk and Fact Check integrations with fail-uncertain responses. Network checks never run automatically on notifications.

## Incomplete / release gates
Android compilation succeeded. Seven local detector tests and five backend tests passed. APK v2 signature verified. Android lint completed with no errors; remaining warnings concern library updates and Kotlin conventions. Real-device behavior, UI, battery and accuracy need testing. No validated ONNX model/tokenizer, Tamil image OCR, isolated redirect worker, RDAP integration, official government-source retrieval, Gemini explanations, signed intelligence updates or PostgreSQL deployment yet. Direct QR camera scanning is not implemented; share a QR image. Low Risk is intentionally withheld while detection is an uncalibrated rules baseline. No rule match means Unverified. No external provider result establishes recipient trust.

Next: test notification access on a real phone, then benchmark and integrate a licensed multilingual model. No real-device or emulator execution has been performed here. Meet the Markdown evaluation targets before claiming results.

## References
https://developer.android.com/reference/android/service/notification/NotificationListenerService
https://developer.android.com/develop/ui/compose/bom
https://developers.google.com/ml-kit/vision/text-recognition/v2
https://docs.cloud.google.com/web-risk/docs/lookup-api
https://developers.google.com/fact-check/tools/api/reference/rest/v1alpha1/claims/search
