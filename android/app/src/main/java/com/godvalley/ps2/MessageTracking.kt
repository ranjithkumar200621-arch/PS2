package com.godvalley.ps2

import java.security.MessageDigest

data class MessageCandidate(val text: String, val sender: String, val time: Long, val conversation: String) {
    fun fingerprint(): String = MessageDigest.getInstance("SHA-256")
        .digest("$conversation\u0000$sender\u0000$time\u0000$text".toByteArray())
        .joinToString("") { "%02x".format(it) }
}
object MessageTracking {
    // All unseen messages are retained, not only the last message of a batch.
    fun fresh(messages: List<MessageCandidate>, since: Long, seen: Set<String>): List<MessageCandidate> =
        messages.filter { it.text.isNotBlank() && it.time >= since && it.fingerprint() !in seen }.distinctBy { it.fingerprint() }
}
