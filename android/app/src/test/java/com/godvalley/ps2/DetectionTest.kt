package com.godvalley.ps2

import org.junit.Assert.*
import org.junit.Test

class DetectionTest {
    @Test fun regionalOtpSafetyNoticeDoesNotWarn() {
        for (text in listOf("OTP யாரிடமும் பகிர வேண்டாம்", "otp anuppathe", "otp share panna koodathu")) assertFalse(text, Detection.analyze(text).warns)
    }
    @Test fun greetingsNeverWarn() { for (text in listOf("hi", "Hi!", "hello", "வணக்கம்", "vanakkam")) assertFalse(text, Detection.analyze(text).warns) }
    @Test fun bankSafetyNoticeDoesNotWarn() { assertFalse(Detection.analyze("Your OTP is 123456. Never share it with anyone.").warns) }
    @Test fun urgentKycLinkWarns() { assertTrue(Detection.analyze("Urgent! Your bank account is blocked. Update KYC at https://example.com").warns) }
    @Test fun directSecretRequestWarns() { assertEquals("High Risk", Detection.analyze("Please send me your OTP to unblock your account").verdict) }
    @Test fun routinePaymentDoesNotWarn() { assertFalse(Detection.analyze("Please pay the electricity bill today").warns) }
    @Test fun tamilAndTanglishSecretRequestsWarn() { for (t in listOf("உங்கள் OTP உடனே அனுப்பு", "otp udanadi anuppu")) assertTrue(Detection.analyze(t).warns) }
    @Test fun keywordCountAloneDoesNotWarn() { assertFalse(Detection.analyze("Urgent payment receipt for account").warns) }
    @Test fun investmentBaitWarns() { assertTrue(Detection.analyze("Guaranteed returns! Invest now to double your money").warns) }
    @Test fun refundTrapWarns() { assertTrue(Detection.analyze("Pay a fee first to receive your refund").warns) }
    @Test fun prizeFeeWarns() { assertTrue(Detection.analyze("You won a prize. Pay a processing fee to claim it").warns) }
    @Test fun lowModelScoreCannotOverrideSecrets() { assertTrue(Detection.analyze("Send me your password", 0.001).warns) }
    @Test fun modelAloneDoesNotFlagGreeting() { assertFalse(Detection.analyze("hi", 0.999).warns) }
    @Test fun modelAloneCannotFlagALink() { assertFalse(Detection.analyze("Our promotion https://example.com", 0.999).warns) }
    @Test fun redactSensitiveContent() { val r=Detection.redact("OTP 123456 me@example.com https://example.com/?otp=123456"); assertFalse(r.contains("123456")); assertFalse(r.contains("me@example.com")); assertFalse(r.contains("https://")) }
    @Test fun ordinaryWordsDoNotMatchPin() { assertFalse(Detection.analyze("shopping payment receipt").warns) }
    @Test fun boundedUrlExtraction() { assertEquals(5, Detection.urls((1..100).joinToString(" ") { "https://example.com/$it" }).size) }
    @Test fun oldScamThenHiOnlyChecksHi() {
        val old = MessageCandidate("send me your OTP", "A", 10, "chat")
        val hi = MessageCandidate("hi", "A", 20, "chat")
        assertEquals(listOf(hi), MessageTracking.fresh(listOf(old, hi), 0, setOf(old.fingerprint())))
    }
    @Test fun allNewMessagesInBatchChecked() {
        val a=MessageCandidate("send me your OTP", "A", 10,"chat"); val b=MessageCandidate("hi","A",20,"chat")
        assertEquals(listOf(a,b),MessageTracking.fresh(listOf(a,b),0,emptySet()))
    }
    @Test fun sameTextInDifferentChatsIsDistinct() {
        val a=MessageCandidate("hi","A",10,"chat1");val b=a.copy(conversation="chat2")
        assertEquals(listOf(b),MessageTracking.fresh(listOf(a,b),0,setOf(a.fingerprint())))
    }
    @Test fun sameTextAtNewTimeIsDistinct() {
        val a=MessageCandidate("hi","A",10,"chat");val b=a.copy(time=20)
        assertEquals(listOf(b),MessageTracking.fresh(listOf(a,b),0,setOf(a.fingerprint())))
    }
    @Test fun skipBeforeMonitoringAndDuplicates() {
        val a=MessageCandidate("old", "A", 10,"chat");val b=a.copy(time=30)
        assertEquals(listOf(b),MessageTracking.fresh(listOf(a,b,b),20,emptySet()))
    }
}
