package com.godvalley.ps2

import android.Manifest
import android.content.*
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.Color
import androidx.lifecycle.lifecycleScope
import androidx.work.*
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import kotlinx.coroutines.*
import kotlinx.coroutines.tasks.await
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

class MainActivity : ComponentActivity() {
    private val incoming = mutableStateOf("")
    private val permission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        receive(intent)
        WorkManager.getInstance(this).enqueueUniquePeriodicWork("retention", ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<Retention>(1, TimeUnit.DAYS).build())
        setContent { MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFFA6E887), background = Color(0xFF081924), surface = Color(0xFF102735))) { Surface { App() } } }
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); receive(intent) }
    private fun receive(i: Intent) {
        if (i.action != Intent.ACTION_SEND) return
        incoming.value = i.getStringExtra(Intent.EXTRA_TEXT)?.take(8000) ?: ""
        val uri = if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            else @Suppress("DEPRECATION") (i.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri)
        if (uri == null || uri.scheme != "content") return
        lifecycleScope.launch {
            try {
                val image = withContext(Dispatchers.IO) {
                    val options = android.graphics.BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    contentResolver.openInputStream(uri)?.use { android.graphics.BitmapFactory.decodeStream(it, null, options) }
                    require(options.outWidth > 0 && options.outHeight > 0)
                    options.inSampleSize = generateSequence(1) { it * 2 }.first { options.outWidth / it <= 2048 && options.outHeight / it <= 2048 }
                    options.inJustDecodeBounds = false
                    val bitmap = contentResolver.openInputStream(uri)?.use { android.graphics.BitmapFactory.decodeStream(it, null, options) } ?: error("Unreadable image")
                    InputImage.fromBitmap(bitmap, 0)
                }
                val qr = BarcodeScanning.getClient()
                val ocr = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
                try {
                    val codes = qr.process(image).await().mapNotNull { it.rawValue }
                    incoming.value = codes.firstOrNull { it.startsWith("upi://", true) }
                        ?: (codes.joinToString("\n") + "\n" + ocr.process(image).await().text).take(8000)
                } finally { qr.close(); ocr.close() }
            } catch (_: Exception) { incoming.value = "Image could not be read. Try a smaller screenshot or share text." }
        }
    }
    @Composable private fun App() {
        val prefs = remember { getSharedPreferences("ps2", MODE_PRIVATE) }
        var enabled by remember { mutableStateOf(prefs.getBoolean("enabled", false)) }
        var result by remember { mutableStateOf<Result?>(null) }
        var history by remember { mutableStateOf(emptyList<Finding>()) }
        var endpoint by remember { mutableStateOf("") }
        var token by remember { mutableStateOf("") }
        var query by remember { mutableStateOf("") }
        var kind by remember { mutableStateOf("claim") }
        var response by remember { mutableStateOf("") }
        var settings by remember { mutableStateOf(false) }
        var busy by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()
        // New or edited input invalidates any earlier local result, reviewed query and server response.
        LaunchedEffect(incoming.value) { result = null; query = ""; kind = "claim"; response = "" }
        LaunchedEffect(Unit) { history = withContext(Dispatchers.IO) { Store.get(this@MainActivity).findings().recent() } }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("PS2", style = MaterialTheme.typography.headlineLarge)
            Text("GOD VALLEY · Protection on your phone")
            Text("Offline screening is available. AI detection and online evidence need additional setup. A warning is advice, not proof of fraud.")
            Text("Notification access exposes available previews from apps you select. PS2 processes them locally and stores reasons for 7 days. Hidden or muted previews may be missed.")
            Row { Checkbox(enabled, { enabled = it; prefs.edit().putBoolean("enabled", it).also { e -> if (it) e.putLong("since", System.currentTimeMillis()) }.apply() }); Text("Enable local monitoring") }
            listOf("WhatsApp" to "com.whatsapp", "Telegram" to "org.telegram.messenger", "Google Messages" to "com.google.android.apps.messaging", "Samsung Messages" to "com.samsung.android.messaging").forEach { (name, pkg) ->
                var checked by remember { mutableStateOf(prefs.getBoolean(pkg, false)) }
                Row { Checkbox(checked, { checked = it; prefs.edit().putBoolean(pkg, it).also { e -> if (it) e.putLong("since", System.currentTimeMillis()) }.apply() }); Text(name) }
            }
            Button(onClick = { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) }) { Text("Grant notification access") }
            Button(onClick = { if (Build.VERSION.SDK_INT >= 33) permission.launch(Manifest.permission.POST_NOTIFICATIONS) }) { Text("Allow warning notifications") }
            Text("Share text or an image to PS2 from another app. Image OCR currently supports Latin text. Tamil image OCR requires a separate validated engine.")
            OutlinedTextField(incoming.value, { incoming.value = it.take(8000) }, label = { Text("Text to check") }, modifier = Modifier.fillMaxWidth())
            Button(onClick = {
                result = Detection.analyze(incoming.value)
                val url = Detection.urls(incoming.value).firstOrNull()?.let(Detection::safeUrl)
                kind = if (url == null) "claim" else "url"
                query = url ?: Detection.redact(incoming.value)
            }) { Text("Check locally") }
            result?.let {
                Text(if (it.clean) "No suspicious signals detected" else it.verdict, style = MaterialTheme.typography.headlineSmall)
                if (!it.clean) Text(it.reasons.joinToString("\n"))
                Text(it.advice)
            }
            Text("Optional online verification", style = MaterialTheme.typography.titleLarge)
            Text(if (endpoint.isBlank()) "Online verification is not connected. Local checks work without it." else "Online verification configured for this session.")
            TextButton(onClick = { settings = !settings }) { Text("Connection settings") }
            Text("Review the query below. Only this query leaves the device when you tap Verify. Remove names and private details. The server also sends it to the selected evidence provider.")
            if (settings) {
            OutlinedTextField(endpoint, { endpoint = it }, label = { Text("Backend HTTPS URL") })
            OutlinedTextField(token, { token = it }, label = { Text("Backend access token") }, visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation())
            }
            Text("Query type: $kind")
            OutlinedTextField(query, { query = it.take(2000) }, label = { Text("Reviewed query") }, modifier = Modifier.fillMaxWidth())
            Button(enabled = !busy && query.isNotBlank() && endpoint.isNotBlank() && token.isNotBlank(), onClick = {
                busy = true
                val approvedQuery = query
                val approvedKind = kind
                val approvedEndpoint = endpoint
                val approvedToken = token
                scope.launch {
                    response = withContext(Dispatchers.IO) {
                        runCatching {
                            val url = URL(approvedEndpoint.trimEnd('/') + "/verify")
                            require(url.protocol == "https" && url.userInfo == null) { "Use an HTTPS backend URL" }
                            val c = url.openConnection() as HttpURLConnection
                            try {
                                c.instanceFollowRedirects = false; c.requestMethod = "POST"; c.doOutput = true
                                c.connectTimeout = 5000; c.readTimeout = 10000
                                c.setRequestProperty("Content-Type", "application/json")
                                c.setRequestProperty("Authorization", "Bearer $approvedToken")
                                c.outputStream.use { it.write(JSONObject().put("kind", approvedKind).put("query", approvedQuery).toString().toByteArray()) }
                                require(c.responseCode == 200) { "Verification unavailable (${c.responseCode})" }
                                c.inputStream.use { stream ->
                                    val bytes = java.io.ByteArrayOutputStream().also { out ->
                                        val buffer = ByteArray(4096)
                                        while (out.size() < 32768) { val count = stream.read(buffer, 0, minOf(buffer.size, 32768 - out.size())); if (count < 0) break; out.write(buffer, 0, count) }
                                    }.toByteArray()
                                    val data = JSONObject(String(bytes, Charsets.UTF_8))
                                    buildString {
                                        appendLine(data.optString("verdict", "Unverified"))
                                        appendLine(data.optString("reason"))
                                        val evidence = data.optJSONArray("evidence")
                                        if (evidence != null) for (i in 0 until evidence.length()) {
                                            val item = evidence.optJSONObject(i)
                                            if (item == null) appendLine(evidence.optString(i)) else {
                                                appendLine(item.optString("claim"))
                                                val reviews = item.optJSONArray("reviews")
                                                if (reviews != null) for (j in 0 until reviews.length()) {
                                                    val review = reviews.getJSONObject(j)
                                                    appendLine("${review.optString("publisher")}: ${review.optString("rating")}")
                                                    appendLine(review.optString("url"))
                                                }
                                            }
                                        }
                                    }
                                }
                            } finally { c.disconnect() }
                        }.getOrElse { "Unverified: ${it.message}" }
                    }
                    busy = false
                }
            }) { Text(if (busy) "Checking…" else "Consent and verify this query") }
            if (response.isNotBlank()) Text(response)
            Text("Recent local warnings", style = MaterialTheme.typography.titleLarge)
            history.forEach { Text("${it.verdict}: ${it.reasons}") }
            Button(onClick = { scope.launch { withContext(Dispatchers.IO) { Store.get(this@MainActivity).findings().purge(Long.MAX_VALUE) }; history = emptyList() } }) { Text("Delete local history") }
        }
    }
}