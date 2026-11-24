package com.godvalley.ps2

import android.net.Uri
import java.text.Normalizer

data class Result(val verdict: String, val reasons: List<String>, val advice: String, val clean: Boolean = false)
object Detection {
    fun rank(verdict: String) = when (verdict) { "High Risk" -> 2; "Suspicious" -> 1; else -> 0 }
    private val groups = listOf(
        "Urgency or threat" to Regex("urgent|immediately|blocked|arrest|digital arrest|parcel detained|உடனே|முடக்க|avasaram|udanadi|block aag", RegexOption.IGNORE_CASE),
        "Sensitive information request" to Regex("\\bkyc\\b|\\botp\\b|password|\\bpin\\b|கடவுச்சொல்|ரகசிய|ragasiya", RegexOption.IGNORE_CASE),
        "Payment or reward request" to Regex("\\bpay\\b|payment|transfer|refund|prize|lottery|பணம்|பரிசு|panam|parisu", RegexOption.IGNORE_CASE)
    )
    fun urls(text: String) = Regex("https?://[^\\s<>]+", RegexOption.IGNORE_CASE).findAll(text.take(8000)).map { it.value.trimEnd('.', ',', ')') }.take(5).toList()
    fun redact(text: String): String = text.take(2000)
        .replace(Regex("https?://[^\\s]+"), "[URL]")
        .replace(Regex("[\\w.+-]+@[\\w.-]+"), "[ADDRESS]")
        .replace(Regex("\\+?\\d[\\d -]{3,}\\d"), "[NUMBER]")
    fun safeUrl(raw: String): String? = runCatching {
        val u = Uri.parse(raw)
        require(u.scheme in listOf("https", "http") && !u.host.isNullOrBlank())
        Uri.Builder().scheme(u.scheme).encodedAuthority(u.host).path(u.path ?: "/").build().toString()
    }.getOrNull()
    fun analyze(raw: String): Result {
        val text = Normalizer.normalize(raw.take(8000), Normalizer.Form.NFKC).replace(Regex("[\\u200B-\\u200D\\uFEFF]"), "")
        if (text.startsWith("upi://", true)) {
            val u = Uri.parse(text)
            val details = listOf("pa", "pn", "am", "cu").mapNotNull { key -> u.getQueryParameter(key)?.take(100)?.let { "$key: $it" } }
            return Result("Unverified", listOf("UPI payment request") + details, "Sending a payment is not required to receive a refund. Verify the recipient independently. A QR code cannot prove trust.")
        }
        val reasons = groups.filter { it.second.containsMatchIn(text) }.map { it.first }.toMutableList()
        if (urls(text).isNotEmpty()) reasons += "Contains a web link"
        val risk = when { reasons.size >= 3 -> "High Risk"; reasons.size >= 2 -> "Suspicious"; else -> "Unverified" }
        if (reasons.isEmpty()) return Result(risk, listOf("No suspicious signals detected"), "This does not prove the message is safe. Only simple rules ran; no trained model or fact check is available on this device. Verify anything unexpected through the official app or website.", clean = true)
        return Result(risk, reasons, "Verify through the official app or website. Never disclose OTP or PIN. Rules can miss scams and flag legitimate messages.")
    }
}