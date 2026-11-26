package com.godvalley.ps2

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.core.app.NotificationCompat
import androidx.core.app.Person
import androidx.room.Room
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    @Test fun tamilScreenshotProducesTamilText() {
        val bitmap=android.graphics.Bitmap.createBitmap(1800,240,android.graphics.Bitmap.Config.ARGB_8888)
        val canvas=android.graphics.Canvas(bitmap);canvas.drawColor(android.graphics.Color.WHITE)
        val paint=android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply { color=android.graphics.Color.BLACK; textSize=90f }
        canvas.drawText("உங்கள் OTP உடனே அனுப்பு",30f,150f,paint)
        try { val text=TamilOcr.read(context,bitmap); assertTrue("Tamil text expected: $text", text.any { it.code in 0x0B80..0x0BFF }) }
        finally { bitmap.recycle() }
    }
    @Test fun encryptedMessageRoundTrip() {
        val raw = "hi from sender; OTP 123456"
        val encrypted = PrivateMessages.encrypt(raw)
        assertFalse(encrypted.contains(raw)); assertEquals(raw, PrivateMessages.decrypt(encrypted))
    }
    @Test fun modelLoadsAndDoesNotFlagHi() {
        val score = SpamModel.score(context, "hi")
        assertNotNull("Bundled ONNX model must load", score)
        assertFalse(Detection.analyze("hi", score).warns)
        assertNull(SpamModel.score(context, "வணக்கம்"))
    }
    @Test fun structuredNotificationSeparatesOldScamAndHi() {
        val sender = Person.Builder().setName("Test sender").build()
        val style = NotificationCompat.MessagingStyle(Person.Builder().setName("Me").build())
            .addMessage("send me your OTP", 10, sender).addMessage("hi", 20, sender)
        val notification = NotificationCompat.Builder(context, "test").setSmallIcon(android.R.drawable.ic_dialog_info).setStyle(style).build()
        val parsed = NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(notification)!!.messages
            .map { MessageCandidate(it.text.toString(), it.person!!.name.toString(), it.timestamp, "conversation") }
        val fresh = MessageTracking.fresh(parsed, 0, setOf(parsed.first().fingerprint()))
        assertEquals(listOf("hi"), fresh.map { it.text }); assertFalse(Detection.analyze(fresh.single().text).warns)
    }
    @Test fun upgradesOriginalHistoryWithoutDeletingIt() = runBlocking {
        val name="migration-fixture.db"
        context.deleteDatabase(name)
        context.openOrCreateDatabase(name, 0, null).use { old ->
            old.execSQL("CREATE TABLE Finding (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, time INTEGER NOT NULL, verdict TEXT NOT NULL, reasons TEXT NOT NULL)")
            old.execSQL("INSERT INTO Finding VALUES (1, 123, 'Suspicious', 'Previous reason')")
            old.version=1
        }
        val upgraded=Room.databaseBuilder(context, Store::class.java, name).addMigrations(Store.migration).build()
        try { assertEquals("Previous reason", upgraded.findings().get(1)!!.reasons); assertEquals("", upgraded.findings().get(1)!!.payload) }
        finally { upgraded.close(); context.deleteDatabase(name) }
    }
    @Test fun storedMessageHasDistinctIdAndDedupPersists() = runBlocking {
        val db=Room.inMemoryDatabaseBuilder(context, Store::class.java).build()
        try {
            val dao=db.findings(); val payload=PrivateMessages.encrypt("{\"text\":\"send OTP\"}")
            val a=dao.add(Finding(time=1, verdict="High Risk", reasons="secret request", payload=payload))
            val b=dao.add(Finding(time=2, verdict="Suspicious", reasons="payment request", payload=payload))
            assertNotEquals(a,b);assertEquals(payload,dao.get(a)!!.payload)
            assertTrue(dao.mark(Seen("fingerprint",1))>0);assertEquals(-1L,dao.mark(Seen("fingerprint",2)))
            dao.purge(Long.MAX_VALUE);assertNull(dao.get(a))
        } finally { db.close() }
    }
}
