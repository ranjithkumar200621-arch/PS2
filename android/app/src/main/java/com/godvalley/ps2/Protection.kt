package com.godvalley.ps2

import android.app.*
import android.content.Context
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
class Protection : NotificationListenerService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val seen = linkedMapOf<String, Long>()
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val prefs = getSharedPreferences("ps2", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("enabled", false) || !prefs.getBoolean(sbn.packageName, false)) return
        val n = sbn.notification
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
        val content = n.extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: n.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: return
        val key = sbn.key + content.hashCode()
        val now = System.currentTimeMillis()
        synchronized(seen) {
            if (now - (seen[key] ?: 0) < 60000) return
            seen[key] = now
            if (seen.size > 100) seen.remove(seen.keys.first())
        }
        scope.launch {
            if (!prefs.getBoolean("enabled", false) || !prefs.getBoolean(sbn.packageName, false)) return@launch
            val r = Detection.analyze(content)
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
    override fun onDestroy() { scope.cancel(); super.onDestroy() }
}
