package com.example.tesskillmobilesecurity

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import android.widget.Toast

class MainActivity : AppCompatActivity() {

    // Kunci rahasia 16 byte dan IV
    private val secretKeyString = "muhammadalfauzan" // Pastikan panjang kunci 16 byte
    private lateinit var secretKey: SecretKey

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Validasi panjang kunci
        if (secretKeyString.length != 16) {
            Toast.makeText(this, "Kunci rahasia harus 16 byte!", Toast.LENGTH_SHORT).show()
            return
        }

        secretKey = AESEncryption.generateKey(secretKeyString)

        val etPlainText = findViewById<EditText>(R.id.et1)
        val etCipherText = findViewById<EditText>(R.id.et2)
        val btnEncrypt = findViewById<Button>(R.id.encryptBtn)
        val btnDecrypt = findViewById<Button>(R.id.decryptBtn)
        val tvEncrypted = findViewById<TextView>(R.id.encryptTV)
        val tvDecrypted = findViewById<TextView>(R.id.decryptTV)

        btnEncrypt.setOnClickListener {
            val plainText = etPlainText.text.toString()
            val iv = AESEncryption.generateIv()
            val encryptedText = AESEncryption.encrypt(plainText, secretKey, iv)
            tvEncrypted.text = encryptedText
            etCipherText.setText(encryptedText)
        }

        btnDecrypt.setOnClickListener {
            val encryptedText = etCipherText.text.toString()
            // ekstrak dari teks terenkripsi
            val iv = AESEncryption.extractIv(encryptedText)
            val cipherText = AESEncryption.extractCipherText(encryptedText)
            val decryptedText = AESEncryption.decrypt(cipherText, secretKey, iv)
            tvDecrypted.text = decryptedText
        }
    }

    object AESEncryption {
        private const val ALGORITHM = "AES"
        private const val CHANGE = "AES/CBC/PKCS5Padding"

        fun generateKey(key: String): SecretKey {
            return SecretKeySpec(key.toByteArray(), ALGORITHM)
        }

        fun generateIv(): IvParameterSpec {
            val iv = ByteArray(16)
            SecureRandom().nextBytes(iv)
            return IvParameterSpec(iv)
        }

        fun encrypt(plainText: String, secretKey: SecretKey, iv: IvParameterSpec): String {
            val cipher = Cipher.getInstance(CHANGE)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
            val encrypted = cipher.doFinal(plainText.toByteArray())
            val ivAndEncrypted = iv.iv + encrypted
            return Base64.encodeToString(ivAndEncrypted, Base64.NO_WRAP)
        }

        fun decrypt(cipherText: String, secretKey: SecretKey, iv: IvParameterSpec): String {
            val cipher = Cipher.getInstance(CHANGE)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
            val decodedBytes = Base64.decode(cipherText, Base64.NO_WRAP)
            val decrypted = cipher.doFinal(decodedBytes)
            return String(decrypted, Charsets.UTF_8)
        }

        fun extractIv(cipherText: String): IvParameterSpec {
            val ivAndEncryptedBytes = Base64.decode(cipherText, Base64.NO_WRAP)
            val ivBytes = ivAndEncryptedBytes.copyOfRange(0, 16)
            return IvParameterSpec(ivBytes)
        }

        fun extractCipherText(cipherText: String): String {
            val ivAndEncryptedBytes = Base64.decode(cipherText, Base64.NO_WRAP)
            return Base64.encodeToString(ivAndEncryptedBytes.copyOfRange(16, ivAndEncryptedBytes.size), Base64.NO_WRAP)
        }
    }
}