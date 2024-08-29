package com.example.tesskillmobilesecurity

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import javax.crypto.Cipher

import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Enkripsi : AppCompatActivity() {

    companion object {
        private const val AES = "AES"
        private const val AES_MODE = "AES/CBC/PKCS5Padding"
        private const val SECRET_KEY = "1234567890123456" // 16 byte key
        private const val INIT_VECTOR = "RandomInitVector" // 16 byte IV

        // Encrypt function
        @Throws(Exception::class)
        fun encrypt(value: String): String {
            val iv = IvParameterSpec(Enkripsi.Companion.INIT_VECTOR.toByteArray(Charsets.UTF_8))
            val skeySpec = SecretKeySpec(
                Enkripsi.Companion.SECRET_KEY.toByteArray(Charsets.UTF_8),
                Enkripsi.Companion.AES
            )

            val cipher = Cipher.getInstance(Enkripsi.Companion.AES_MODE)
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv)

            val encrypted = cipher.doFinal(value.toByteArray())
            return Base64.encodeToString(encrypted, Base64.DEFAULT)
        }

        // Decrypt function
        @Throws(Exception::class)
        fun decrypt(encrypted: String): String {
            val iv = IvParameterSpec(Enkripsi.Companion.INIT_VECTOR.toByteArray(Charsets.UTF_8))
            val skeySpec = SecretKeySpec(
                Enkripsi.Companion.SECRET_KEY.toByteArray(Charsets.UTF_8),
                Enkripsi.Companion.AES
            )

            val cipher = Cipher.getInstance(Enkripsi.Companion.AES_MODE)
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv)

            val original = cipher.doFinal(Base64.decode(encrypted, Base64.DEFAULT))
            return String(original)
        }
    }

    @SuppressLint("MissingInflatedId")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_enkripsi)

        val textView: TextView = findViewById(R.id.textView)

        try {
            val originalText = "Hello, Android Developer!"
            Log.d("AES", "Original Text: $originalText")

            // Encrypt
            val encryptedText = Enkripsi.Companion.encrypt(originalText)
            Log.d("AES", "Encrypted Text: $encryptedText")

            // Decrypt
            val decryptedText = Enkripsi.Companion.decrypt(encryptedText)
            Log.d("AES", "Decrypted Text: $decryptedText")

            textView.text = "Original: $originalText\nEncrypted: $encryptedText\nDecrypted: $decryptedText"

        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("AES", "Error: ${e.message}")
        }
    }
}
