package com.godvalley.ps2

import org.junit.Assert.*
import org.junit.Test

class DetectionTest {
    @Test fun urgentKycLinkWarns() {
        assertEquals("High Risk", Detection.analyze("Urgent KYC update or account blocked https://example.com").verdict)
    }
    @Test fun plainMessageDoesNotClaimSafety() {
        assertEquals("Unverified", Detection.analyze("Meet at the library after class").verdict)
    }
    @Test fun tamilAndTanglishSignals() {
        assertEquals("Suspicious", Detection.analyze("உடனே பணம் அனுப்பு").verdict)
        assertEquals("Suspicious", Detection.analyze("avasaram panam anuppu").verdict)
    }
    @Test fun redactSensitiveContent() {
        val result = Detection.redact("OTP 123456 email me@example.com visit https://example.com/?otp=123456")
        assertFalse(result.contains("123456")); assertFalse(result.contains("me@example.com")); assertFalse(result.contains("https://"))
    }
    @Test fun invisibleCharactersDoNotHideUrgency() {
        assertEquals("Suspicious", Detection.analyze("ur\u200bgent payment").verdict)
    }
    @Test fun ordinaryWordsDoNotMatchPin() {
        assertEquals("Unverified", Detection.analyze("shopping payment receipt").verdict)
    }
    @Test fun boundedUrlExtraction() {
        assertEquals(5, Detection.urls((1..100).joinToString(" ") { "https://example.com/$it" }).size)
    }
}
