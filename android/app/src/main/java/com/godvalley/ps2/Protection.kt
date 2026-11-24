package com.godvalley.ps2

import android.app.*
import android.content.Context
import android.content.SharedPreferences
import android.content.Intent
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.room.*
import androidx.work.*
import kotlinx.coroutines.*
import java.util.concurrent.TimeUnit

@Entity data class Finding(@PrimaryKey(autoGenerate = true) val id: Long = 0, val time: Long, val verdict: String, val reasons: String)
@Dao interface Findings {
    @Insert suspend fun add(item: Finding)
    @Query("SELECT * FROM Finding ORDER BY time DESC LIMIT 30") suspend fun recent(): List<Finding>
    @Query("DELETE FROM Finding WHERE time < :cutoff") suspend fun purge(cutoff: Long)
}
@Database(entities = [Finding::class], version = 1, exportSchema = false)
abstract class Store : RoomDatabase() {
    abstract fun findings(): Findings
    companion object {
        @Volatile private var instance: Store? = null
        fun get(c: Context): Store = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(c.applicationContext, Store::class.java, "ps2.db").build().also { instance = it }
        }
    }
}
class Retention(c: Context, p: WorkerParameters) : CoroutineWorker(c, p) {
    override suspend fun doWork(): androidx.work.ListenableWorker.Result {
        Store.get(applicationContext).findings().purge(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(7))
        return androidx.work.ListenableWorker.Result.success()
    }
}
/** Ledger storage in app-private preferences: salted digests and timestamps only, never message text. */
class PrefsLedgerStore(private val prefs: SharedPreferences) : LedgerStore {
    override var salt: String
        get() = prefs.getString("ledger_salt", null) ?: ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }.also { prefs.edit().putString("ledger_salt", it).apply() }
        set(v) { prefs.edit().putString("ledger_salt", v).apply() }
    override var since: Long
        get() = prefs.getLong("since", 0L)
        set(v) { prefs.edit().putLong("since", v).apply() }
    override fun load(): Map<String, Long> = (prefs.getString("ledger", "") ?: "").lineSequence()
        .mapNotNull { it.split(',').takeIf { p -> p.size == 2 }?.let { p -> p[1].toLongOrNull()?.let { t -> p[0] to t } } }.toMap()
    override fun save(entries: Map<String, Long>) {
        prefs.edit().putString("ledger", entries.entries.joinToString("\n") { "${it.key},${it.value}" }).apply()
    }
}
class Protection : NotificationListenerService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val prefs by lazy { getSharedPreferences("ps2", Context.MODE_PRIVATE) }
    private val ledger by lazy { MessageLedger(PrefsLedgerStore(prefs)) }
    private fun active(pkg: String) = prefs.getBoolean("enabled", false) && prefs.getBoolean(pkg, false)

    /** Permission revoked or listener unbound: anything that arrives later must not make old history look new. */
    override fun onListenerDisconnected() { prefs.edit().putBoolean("gap", true).apply(); ledger.rebase() }
    override fun onListenerConnected() { ledger.rebase(); prefs.edit().putBoolean("gap", false).apply() }

    /** Extract structured MessagingStyle messages, or one current plain-text fallback. */
    private fun extract(sbn: StatusBarNotification): List<Incoming> {
        val n = sbn.notification
        if (NotificationContent.isGroupSummary(n.flags)) return emptyList()
        NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(n)?.let { style ->
            val self = style.user
            return style.messages.mapNotNull { m ->
                val person = m.person
                val text = m.text?.toString()?.trim()?.take(2000)
                if (text.isNullOrBlank() || person == null || person === self) return@mapNotNull null
                if (person.key == style.user.key && style.user.key != null) return@mapNotNull null
                val sender = person.key ?: person.name?.toString()?.take(200) ?: "unknown"
                val conversation = sbn.notification.getGroup() ?: sbn.packageName + "/" + sbn.key
                val timestamp = m.timestamp.takeIf { it > 0L } ?: 0L
                Incoming(conversation, timestamp, sender, text)
            }
        }
        val textLines = n.extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
            ?.mapNotNull { it?.toString()?.trim()?.takeIf(String::isNotBlank) }
        val text = NotificationContent.latestPlainText(
            latest = n.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString(),
            textLines = textLines
        )
        val conversation = n.getGroup()?.takeIf { it.isNotBlank() } ?: sbn.packageName + "/" + sbn.key
        return if (text.isNullOrBlank()) emptyList() else listOf(Incoming(conversation, 0L, "plain", text))
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (!active(sbn.packageName)) return
        val items = extract(sbn)
        if (items.isEmpty()) return
        val now = System.currentTimeMillis()
        scope.launch {
            val r = Screening.process(ledger, items, active(sbn.packageName)) ?: return@launch
            if (r.verdict !in listOf("Suspicious", "High Risk")) return@launch
            Store.get(this@Protection).findings().add(Finding(time = now, verdict = r.verdict, reasons = r.reasons.joinToString("; ")))
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel("risk", "Scam warnings", NotificationManager.IMPORTANCE_HIGH))
            val open = PendingIntent.getActivity(this@Protection, 0, Intent(this@Protection, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            val alert = NotificationCompat.Builder(this@Protection, "risk")
                .setSmallIcon(android.R.drawable.ic_dialog_alert).setContentTitle("PS2: ${r.verdict}")
                .setContentText("Potential scam signals detected. Open PS2 for reasons.")
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setContentIntent(open).setAutoCancel(true).build()
            try { NotificationManagerCompat.from(this@Protection).notify(sbn.key.hashCode(), alert) } catch (_: SecurityException) { }
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        try { NotificationManagerCompat.from(this).cancel(sbn.key.hashCode()) } catch (_: SecurityException) { }
    }

    override fun onDestroy() { scope.cancel(); super.onDestroy() }
}