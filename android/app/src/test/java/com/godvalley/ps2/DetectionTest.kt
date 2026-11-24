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

    @Test fun oldScamAndNewGreetingOnlyScreensGreeting() {
        var now = 20_000L
        val store = TestLedgerStore()
        val ledger = MessageLedger(store) { now }
        store.since = 10_000L
        val result = Screening.process(ledger, listOf(
            Incoming("chat-1", 1_000L, "sender", "Urgent KYC link https://example.com"),
            Incoming("chat-1", 15_000L, "sender", "hi")
        ), true)
        assertNull(result)
    }

    @Test fun scamAfterHarmlessMessageIsDetected() {
        val ledger = MessageLedger(TestLedgerStore()) { 20_000L }
        val result = Screening.process(ledger, listOf(
            Incoming("chat-1", 15_000L, "sender", "hi"),
            Incoming("chat-1", 16_000L, "sender", "Urgent KYC link https://example.com")
        ), true)
        assertEquals("High Risk", result?.verdict)
    }

    @Test fun repostedNotificationIsNotScreenedAgain() {
        var now = 20_000L
        val ledger = MessageLedger(TestLedgerStore()) { now }
        val item = Incoming("chat-1", 15_000L, "sender", "hi")
        assertNull(Screening.process(ledger, listOf(item), true))
        assertNull(Screening.process(ledger, listOf(item), true))
    }

    @Test fun multipleConversationsAndGroupedMessagesRemainSeparate() {
        val ledger = MessageLedger(TestLedgerStore()) { 20_000L }
        val result = Screening.process(ledger, listOf(
            Incoming("chat-1", 15_000L, "sender-a", "hi"),
            Incoming("chat-2", 16_000L, "sender-b", "Urgent payment https://example.com")
        ), true)
        assertEquals("High Risk", result?.verdict)
    }

    @Test fun monitoringGapRebasesBeforeOldHistory() {
        val store = TestLedgerStore()
        val ledger = MessageLedger(store) { 20_000L }
        ledger.rebase()
        assertNull(Screening.process(ledger, listOf(Incoming("chat-1", 15_000L, "sender", "Urgent KYC link")), true))
    }

    @Test fun latestPlainTextDoesNotAnalyzeExpandedHistory() {
        assertEquals("hi", NotificationContent.latestPlainText("hi", listOf("Old scam", "hi")))
        assertEquals("hi", NotificationContent.latestPlainText(null, listOf("Old scam", "hi")))
        assertEquals("", NotificationContent.latestPlainText("", emptyList()) ?: "")
    }

    @Test fun harmlessGreetingIsClearAndNonAlarming() {
        val result = Detection.analyze("hi")
        assertTrue(result.clean)
        assertEquals("No suspicious signals detected", result.reasons.single())
        assertTrue(result.advice.contains("does not prove"))
    }

    @Test fun pausedMonitoringRejectsNotifications() {
        val ledger = MessageLedger(TestLedgerStore()) { 20_000L }
        assertNull(Screening.process(ledger, listOf(Incoming("chat", 15_000L, "sender", "Urgent KYC link")), false))
    }

    @Test fun multipleUnseenMessagesAreAllCandidates() {
        val ledger = MessageLedger(TestLedgerStore()) { 30_000L }
        val result = Screening.process(ledger, listOf(
            Incoming("chat", 21_000L, "sender", "hello"),
            Incoming("chat", 22_000L, "sender", "your account is blocked"),
            Incoming("chat", 23_000L, "sender", "send OTP at https://example.com")
        ), true)
        assertEquals("High Risk", result?.verdict)
    }

    @Test fun plainRepostIsSuppressed() {
        val ledger = MessageLedger(TestLedgerStore()) { 20_000L }
        val plain = Incoming("chat", 0L, "plain", "hello")
        assertNull(Screening.process(ledger, listOf(plain), true))
        assertNull(Screening.process(ledger, listOf(plain), true))
    }

    private class TestLedgerStore : LedgerStore {
        override var salt = "test-salt"
        override var since = 0L
        private var entries = emptyMap<String, Long>()
        override fun load(): Map<String, Long> = entries
        override fun save(entries: Map<String, Long>) { this.entries = entries }
    }
}
