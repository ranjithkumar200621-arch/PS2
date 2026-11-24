package com.godvalley.ps2
import org.junit.Test
import org.junit.Assert.*
import java.io.File
class TokenizerTest {
@Test fun matchesPublishedTokenizer() {
val vocab=File("src/main/assets/spam-vocab.txt").readLines().withIndex().associate { it.value to it.index }
val tokenizer=WordPiece(vocab)
assertArrayEquals(longArrayOf(101L,7632L,102L), tokenizer.encode("hi"))
assertArrayEquals(longArrayOf(101L,7592L,1010L,2088L,999L,102L), tokenizer.encode("Hello, world!"))
assertArrayEquals(longArrayOf(101L,2115L,27178L,2361L,2003L,13138L,19961L,2575L,1012L,2196L,3745L,2009L,1012L,102L), tokenizer.encode("Your OTP is 123456. Never share it."))
assertArrayEquals(longArrayOf(101L,3477L,1037L,7408L,2005L,1037L,25416L,8630L,2012L,16770L,1024L,1013L,1013L,2742L,1012L,4012L,1013L,1037L,1029L,1038L,1027L,1016L,102L), tokenizer.encode("PAY a fee for a refund at https://example.com/a?b=2"))
assertArrayEquals(longArrayOf(101L,2123L,1005L,1056L,3745L,20786L,2015L,1012L,102L), tokenizer.encode("Don't share passwords."))
}
}