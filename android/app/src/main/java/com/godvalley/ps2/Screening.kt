package com.godvalley.ps2

import java.security.MessageDigest
import java.text.Normalizer

/** One message as exposed by a notification. Held in memory only; never persisted. */
data class Incoming(val conversation: String, val time: Long, val sender: String, val text: String)

/** Plain notification extras can contain accumulated history. Prefer EXTRA_TEXT and TEXT_LINES; never scan BIG_TEXT as new text. */
object NotificationContent {
    fun latestPlainText(latest: String?, textLines: List<String>?): String? {
        latest?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        textLines?.lastOrNull()?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        return null
    }

    fun isGroupSummary(flags: Int): Boolean = (flags and android.app.Notification.FLAG_GROUP_SUMMARY) != 0
}

/** Persistence for the ledger. Implementations store only what they are given: salted digests and timestamps. */
interface LedgerStore {
    var salt: String
    /** Messages sent before this instant are ignored (monitoring was off or the listener was disconnected). */
    var since: Long
    fun load(): Map<String, Long>
    fun save(entries: Map<String, Long>)
}

/**
 * Remembers which messages were already screened, using salted SHA-256 digests only.
 * Identity of a message is (conversation, sender, message time, normalized text). Timed messages are
 * remembered for [TIMED_TTL]. Plain notification fallbacks with no message timestamp are reposted
 * only for [UNTIMED_WINDOW], because they cannot establish whether identical text is truly new.
 */
class MessageLedger(private val store: LedgerStore, private val clock: () -> Long = System::currentTimeMillis) {
    private val seen = LinkedHashMap<String, Long>().apply { putAll(store.load()) }

    /** Marks a gap in monitoring so history already present in notifications is not treated as new. */
    @Synchronized fun rebase() { store.since = clock() }

    /** Returns only messages not seen before, in arrival order, and records them. */
    @Synchronized fun fresh(items: List<Incoming>): List<Incoming> {
        val now = clock()
        val since = store.since
        var changed = seen.entries.removeAll { now - it.value > TIMED_TTL }
        val out = ArrayList<Incoming>()
        for (m in items) {
            if (m.text.isBlank() || (m.time in 1 until since)) continue
            val digest = digest(m)
            val previous = seen[digest]
            val repost = previous != null && (m.time > 0 || now - previous < UNTIMED_WINDOW)
            if (repost) continue
            seen.remove(digest); seen[digest] = now; changed = true
            out += m
        }
        while (seen.size > MAX_ENTRIES) { seen.remove(seen.keys.first()); changed = true }
        if (changed) store.save(seen)
        return out
    }

    private fun digest(m: Incoming): String {
        val normalized = Normalizer.normalize(m.text.take(2000), Normalizer.Form.NFKC)
            .replace(Regex("[\\u200B-\\u200D\\uFEFF]"), "")
            .trim().replace(Regex("\\s+"), " ")
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest("${store.salt}\u0000${m.conversation}\u0000${m.sender}\u0000${m.time}\u0000${normalized}".toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    companion object {
        const val TIMED_TTL = 30L * 24 * 60 * 60 * 1000
        const val UNTIMED_WINDOW = 10L * 60 * 1000
        const val MAX_ENTRIES = 2000
    }
}

object Screening {
    /**
     * Screens every unseen message. Returns null when monitoring is off or nothing is new.
     * Each unseen message is analysed alone, and unseen messages from one sender in one conversation
     * are also analysed together, so a split scam is not missed by reducing a batch to its final message.
     */
    fun process(ledger: MessageLedger, items: List<Incoming>, monitoring: Boolean, analyze: (String) -> Result = Detection::analyze): Result? {
        if (!monitoring) return null
        val fresh = ledger.fresh(items)
        if (fresh.isEmpty()) return null
        val candidates = fresh.map { it.text } +
            fresh.groupBy { it.conversation to it.sender }.values.filter { it.size > 1 }.map { g -> g.joinToString("\n") { it.text } }
        val strongest = candidates.map(analyze).maxByOrNull { Detection.rank(it.verdict) }
        return strongest?.takeIf { Detection.rank(it.verdict) > 0 }
    }
}