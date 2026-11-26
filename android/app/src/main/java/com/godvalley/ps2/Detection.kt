package com.godvalley.ps2

import android.net.Uri
import java.text.Normalizer
import java.util.Locale

data class Result(val verdict: String, val reasons: List<String>, val advice: String, val model: String = "Context rules") {
    val warns get() = verdict == "Suspicious" || verdict == "High Risk"
}
object Detection {
    fun urls(text: String) = Regex("https?://[^\\s<>]+", RegexOption.IGNORE_CASE).findAll(text.take(8000)).map { it.value.trimEnd('.', ',', ')') }.take(5).toList()
    fun redact(text: String): String = text.take(2000)
        .replace(Regex("https?://[^\\s]+"), "[URL]")
        .replace(Regex("[\\w.+-]+@[\\w.-]+"), "[ADDRESS]")
        .replace(Regex("\\+?\\d[\\d -]{3,}\\d"), "[NUMBER]")
    fun safeUrl(raw: String): String? = runCatching {
        val u = Uri.parse(raw)
        require(u.scheme in listOf("https", "http") && !u.host.isNullOrBlank() && u.userInfo == null)
        u.buildUpon().clearQuery().fragment(null).build().toString()
    }.getOrNull()
    fun analyze(raw: String, spamScore: Double? = null): Result {
        val text = Normalizer.normalize(raw.take(8000), Normalizer.Form.NFKC)
            .replace(Regex("[\\u200B-\\u200D\\uFEFF]"), "").trim().lowercase(Locale.ROOT)
        if (text.isBlank()) return Result("No text to check", emptyList(), "Enter a message or share text to PS2.")
        if (text.startsWith("upi://")) return runCatching {
            val u = Uri.parse(raw.trim())
            val details = listOf("pa" to "Payee address", "pn" to "Payee name", "am" to "Amount", "cu" to "Currency")
                .mapNotNull { (key, label) -> u.getQueryParameter(key)?.take(100)?.let { "$label: $it" } }
            Result("Unverified", listOf("This QR requests a UPI payment") + details, "Confirm the payee and amount in your payment app. Scanning a QR and entering a PIN sends money; a QR cannot prove recipient trust.")
        }.getOrElse { Result("Unverified", listOf("Could not decode this payment QR"), "Do not pay until the recipient and amount are clear.") }
        fun has(p: String) = Regex(p, RegexOption.IGNORE_CASE).containsMatchIn(text)
        val link = urls(text).isNotEmpty()
        val urgent = has("\\b(urgent|immediately|blocked|suspended|arrest|today|now)\\b|உடனே|முடக்க|avasaram|udanadi|block aag")
        val account = has("\\b(kyc|bank|account|aadhaar)\\b|வங்கி|கணக்கு")
        val action = has("\\b(click|update|verify|send|share|pay|transfer|deposit|claim|scan|invest)\\b|அனுப்பு|செலுத்த|பகிர|anuppu|seluthu|click pannu")
        val pay = has("\\b(pay|payment|transfer|deposit|fee|money)\\b|பணம்|கட்டணம்|panam|kattanam")
        val negative = "(?:never|do not|don't|dont|not to)"
        val directSecrets = text.split(Regex("[.!?\\n]")).any { sentence ->
            !Regex("$negative.{0,20}(share|send|tell|give|disclose)|(அனுப்ப|பகிர|சொல்ல).{0,12}(வேண்டாம்|கூடாது|ாதீர்கள்)|anuppathe|sollathe|share.{0,12}(pannathe|koodathu)").containsMatchIn(sentence) &&
                Regex("\\b(share|send|tell|give|disclose)\\b.{0,45}\\b(otp|pin|password|verification code)\\b|\\b(otp|pin|password)\\b.{0,25}(அனுப்பு|பகிர|anuppu|sollu)").containsMatchIn(sentence)
        }
        val reasons = mutableListOf<String>()
        if (directSecrets) reasons += "Asks you to disclose an OTP, PIN or password"
        if (link && account && urgent && action) reasons += "Combines account pressure with a link asking you to act"
        if (has("refund|receive money|cashback|திரும்ப|refund") && pay && action && has("first|receive|claim|release|முதலில்|mudhal|scan|pin")) reasons += "Asks for a payment or PIN to receive a refund or money"
        if (has("digital arrest|police|customs|cbi|parcel detained|கைது") && pay && action) reasons += "Uses an authority or arrest claim to demand payment"
        if (has("prize|lottery|winner|won|பரிசு|parisu") && pay && action) reasons += "Requests a payment or fee to claim a prize"
        if (has("guaranteed|risk.free|double your|100% return") && has("invest|profit|return|money") && (action || link)) reasons += "Promises guaranteed investment returns while requesting action"
        if (has("remote access|anydesk|teamviewer|screen.?share") && has("bank|refund|support") && has("install|download|enable")) reasons += "Requests remote device access in a banking or refund context"
        val verdict = when { directSecrets || reasons.size >= 2 -> "High Risk"; reasons.isNotEmpty() -> "Suspicious"; link || pay || account -> "Unverified"; else -> "No suspicious signals" }
        val advice = when (verdict) {
            "High Risk", "Suspicious" -> "This specific message looks suspicious. Do not use its link or send money or secrets. Verify independently through the official app. This is a warning, not proof of fraud."
            "Unverified" -> "There is not enough evidence to judge this message. A link or payment term alone does not prove fraud."
            else -> "No suspicious pattern was found in this message. This does not guarantee safety."
        }
        return Result(verdict, reasons, advice, if (spamScore != null) "Context rules; OTIS spam score is advisory only" else "Context rules; English model not used")
    }
}
