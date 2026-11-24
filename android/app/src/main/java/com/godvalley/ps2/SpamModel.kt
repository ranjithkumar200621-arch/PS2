package com.godvalley.ps2

import android.content.Context
import ai.onnxruntime.*
import java.nio.LongBuffer
import java.util.Locale
import kotlin.math.exp

class WordPiece(private val vocab: Map<String, Int>) {
    fun encode(text: String): LongArray {
        val result = mutableListOf(101L)
        for (word in Regex("[a-z0-9]+|[^a-z0-9\\s]").findAll(text.lowercase(Locale.ROOT)).map { it.value }) {
            if (result.size >= 127) break
            val pieces = mutableListOf<Long>(); var start = 0
            if (word.length > 100) { result += 100L; continue }
            while (start < word.length) {
                var end = word.length; var found: Int? = null
                while (end > start) { found = vocab[(if (start > 0) "##" else "") + word.substring(start, end)]; if (found != null) break; end-- }
                if (found == null) { pieces.clear(); pieces += 100L; break }
                pieces += found.toLong(); start = end
            }
            result += pieces.take(127 - result.size)
        }
        result += 102L
        return result.toLongArray()
    }
}
object SpamModel {
    private var session: OrtSession? = null
    private var tokenizer: WordPiece? = null
    private var failed = false
    // This model was trained on English. Never interpret its score as a fraud probability.
    @Synchronized fun score(context: Context, text: String): Double? {
        if (failed || text.any { it.code > 127 } || text.isBlank() || Regex("\\b(anuppu|panam|parisu|avasaram|udanadi|vanakkam|sollu|pannu)\\b", RegexOption.IGNORE_CASE).containsMatchIn(text)) return null
        return runCatching {
            val env = OrtEnvironment.getEnvironment()
            if (session == null) {
                val vocab = context.assets.open("spam-vocab.txt").bufferedReader().use { it.readLines() }.withIndex().associate { it.value to it.index }
                tokenizer = WordPiece(vocab)
                OrtSession.SessionOptions().use { opts ->
                    opts.setIntraOpNumThreads(2)
                    session = env.createSession(context.assets.open("spam.onnx").use { it.readBytes() }, opts)
                }
            }
            val ids = tokenizer!!.encode(text.take(8000)); val shape = longArrayOf(1, ids.size.toLong())
            OnnxTensor.createTensor(env, LongBuffer.wrap(ids), shape).use { input ->
                OnnxTensor.createTensor(env, LongBuffer.wrap(LongArray(ids.size) { 1 }), shape).use { mask ->
                    OnnxTensor.createTensor(env, LongBuffer.wrap(LongArray(ids.size)), shape).use { types ->
                        val all = mapOf("input_ids" to input, "attention_mask" to mask, "token_type_ids" to types)
                        session!!.run(all.filterKeys { it in session!!.inputNames }).use { result ->
                            @Suppress("UNCHECKED_CAST") val logits = (result[0].value as Array<FloatArray>)[0]
                            1.0 / (1.0 + exp((logits[0] - logits[1]).toDouble()))
                        }
                    }
                }
            }
        }.getOrElse { failed = true; null }
    }
}
