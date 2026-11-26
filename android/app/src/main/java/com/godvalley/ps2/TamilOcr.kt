package com.godvalley.ps2

import android.content.Context
import android.graphics.Bitmap
import com.googlecode.tesseract.android.TessBaseAPI
import java.io.File

object TamilOcr {
    @Synchronized fun read(context: Context, bitmap: Bitmap): String {
        val root=File(context.noBackupFilesDir, "ocr")
        val data=File(root,"tessdata").apply { mkdirs() }
        for (lang in listOf("tam","eng")) {
            val target=File(data,"$lang.traineddata")
            if (!target.exists()) {
                val temporary=File(data,"$lang.tmp")
                context.assets.open("$lang.traineddata").use { input -> temporary.outputStream().use { input.copyTo(it) } }
                check(temporary.renameTo(target))
            }
        }
        val engine=TessBaseAPI()
        return try {
            check(engine.init(root.absolutePath,"tam+eng")) { "Could not load Tamil OCR" }
            engine.setImage(bitmap)
            engine.utF8Text.orEmpty().take(8000)
        } finally { engine.recycle() }
    }
}
