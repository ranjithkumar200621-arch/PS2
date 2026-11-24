package com.godvalley.ps2

import android.app.*
import android.content.Context
import android.content.Intent
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.work.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.util.concurrent.TimeUnit

@Entity data class Finding(@PrimaryKey(autoGenerate = true) val id: Long = 0, val time: Long, val verdict: String, val reasons: String,
    @ColumnInfo(defaultValue = "''") val payload: String = "", @ColumnInfo(defaultValue = "''") val advice: String = "", @ColumnInfo(defaultValue = "''") val feedback: String = "")
@Entity data class Seen(@PrimaryKey val fingerprint: String, val time: Long)
@Dao interface Findings {
    @Insert suspend fun add(item: Finding): Long
    @Query("SELECT * FROM Finding WHERE time >= :cutoff ORDER BY time DESC LIMIT 100") fun recent(cutoff: Long): Flow<List<Finding>>
    @Query("SELECT * FROM Finding WHERE id = :id") suspend fun get(id: Long): Finding?
    @Query("DELETE FROM Finding WHERE time < :cutoff") suspend fun purge(cutoff: Long)
    @Query("UPDATE Finding SET feedback = :value WHERE id = :id") suspend fun feedback(id: Long, value: String)
    @Insert(onConflict = OnConflictStrategy.IGNORE) suspend fun mark(item: Seen): Long
    @Query("DELETE FROM Seen WHERE time < :cutoff") suspend fun prune(cutoff: Long)
}
@Database(entities = [Finding::class, Seen::class], version = 2, exportSchema = false)
abstract class Store : RoomDatabase() {
    abstract fun findings(): Findings
    companion object {
        @Volatile private var instance: Store? = null
        val migration = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                for (column in listOf("payload", "advice", "feedback")) db.execSQL("ALTER TABLE Finding ADD COLUMN $column TEXT NOT NULL DEFAULT ''")
                db.execSQL("CREATE TABLE IF NOT EXISTS Seen (fingerprint TEXT NOT NULL PRIMARY KEY, time INTEGER NOT NULL)")
            }
        }
        fun get(c: Context): Store = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(c.applicationContext, Store::class.java, "ps2.db").addMigrations(migration).build().also { instance = it }
        }
    }
}
object PrivateMessages {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return (store.getKey("ps2-message-history", null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("ps2-message-history", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    @Synchronized fun encrypt(text: String): String = Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.ENCRYPT_MODE, key()); Base64.encodeToString(iv + doFinal(text.toByteArray()), Base64.NO_WRAP)
    }
    @Synchronized fun decrypt(value: String): String = runCatching {
        val bytes = Base64.decode(value, Base64.NO_WRAP)
        Cipher.getInstance("AES/GCM/NoPadding").run { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12))); String(doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8) }
    }.getOrDefault("{}")
}
class Retention(c: Context, p: WorkerParameters) : CoroutineWorker(c, p) {
    override suspend fun doWork(): androidx.work.ListenableWorker.Result {
        val dao = Store.get(applicationContext).findings(); val cutoff = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(7)
        dao.purge(cutoff); dao.prune(cutoff)
        return androidx.work.ListenableWorker.Result.success()
    }
}
class Protection : NotificationListenerService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val prefs = getSharedPreferences("ps2", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("enabled", false) || !prefs.getBoolean(sbn.packageName, false)) return
        val n = sbn.notification
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
        val since = prefs.getLong("monitorSince", System.currentTimeMillis()).also { if (!prefs.contains("monitorSince")) prefs.edit().putLong("monitorSince", it).apply() }
        val title = n.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty().take(120)
        val style = runCatching { NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(n) }.getOrNull()
        val messages = if (style != null) style.messages.mapNotNull { msg ->
            if (msg.person == null) null else msg.text?.toString()?.let { MessageCandidate(it.take(8000), msg.person?.name?.toString().orEmpty().take(120), msg.timestamp, sbn.key) }
        } else {
            // Expanded inbox text can contain old messages. Never concatenate it.
            val text = n.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            if (text.isNullOrBlank() || text.contains('\n')) emptyList() else listOf(MessageCandidate(text.take(8000), title, if (n.`when` > 0) n.`when` else sbn.postTime, sbn.key))
        }
        scope.launch { mutex.withLock {
            val dao = Store.get(this@Protection).findings()
            for (message in MessageTracking.fresh(messages, since, emptySet())) {
                if (!prefs.getBoolean("enabled", false) || !prefs.getBoolean(sbn.packageName, false)) return@withLock
                if (dao.mark(Seen(message.fingerprint(), System.currentTimeMillis())) == -1L) continue
                val r = Detection.analyze(message.text, SpamModel.score(this@Protection, message.text))
                if (!r.warns) continue
                val source = when(sbn.packageName) { "com.whatsapp" -> "WhatsApp"; "org.telegram.messenger" -> "Telegram"; "com.google.android.apps.messaging" -> "Messages"; else -> "Messages" }
                val payload = PrivateMessages.encrypt(JSONObject().put("text", message.text).put("sender", message.sender).put("source", source).put("model", r.model).toString())
                val id = dao.add(Finding(time = message.time, verdict = r.verdict, reasons = r.reasons.joinToString("\n"), payload = payload, advice = r.advice))
                val manager = getSystemService(NotificationManager::class.java)
                manager.createNotificationChannel(NotificationChannel("risk", "Scam warnings", NotificationManager.IMPORTANCE_HIGH))
                val intent = Intent(this@Protection, MainActivity::class.java).putExtra("findingId", id).setData(android.net.Uri.parse("ps2://finding/$id"))
                val open = PendingIntent.getActivity(this@Protection, id.toInt(), intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                val preview = Detection.redact(message.text).replace('\n', ' ').take(180)
                val publicNotice = NotificationCompat.Builder(this@Protection, "risk").setSmallIcon(android.R.drawable.ic_dialog_alert).setContentTitle("PS2 message warning").setContentText("Unlock to see the message and reasons.").build()
                val alert = NotificationCompat.Builder(this@Protection, "risk").setSmallIcon(android.R.drawable.ic_dialog_alert)
                    .setContentTitle("$source: this message looks suspicious")
                    .setContentText("${message.sender}: $preview")
                    .setStyle(NotificationCompat.BigTextStyle().bigText("${message.sender}: $preview\n${r.reasons.joinToString("\n")}\nTap to review this message."))
                    .setTimeoutAfter(TimeUnit.DAYS.toMillis(7)).setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setPublicVersion(publicNotice).setContentIntent(open).setAutoCancel(true).build()
                try { NotificationManagerCompat.from(this@Protection).notify(id.toInt(), alert) } catch (_: SecurityException) { }
            }
            dao.purge(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(7)); dao.prune(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(7))
        } }
    }
    override fun onDestroy() { scope.cancel(); super.onDestroy() }
}
