package com.example.tesskillmobilesecurity

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

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
        val chiperText = Cipher.getInstance(CHANGE)
        chiperText.init(Cipher.ENCRYPT_MODE, secretKey, iv)
        val encrypted = chiperText.doFinal(plainText.toByteArray())
        return Base64.getEncoder().encodeToString(encrypted)
    }

    // Fungsi dekripsi
    fun decrypt(cipherText: String, secretKey: SecretKey, iv: IvParameterSpec): String {
        val cipher = Cipher.getInstance(CHANGE)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
        val decodedBytes = Base64.getDecoder().decode(cipherText)
        val decrypted = cipher.doFinal(decodedBytes)
        return String(decrypted)
    }
}
    fun main () {
        val secretKeyString = "muhammadalfauzan"
        val secretKey = AESEncryption.generateKey(secretKeyString)

        val iv = AESEncryption.generateIv()
        val plainText = "Hello, Fauzan"

        val encryptedText = AESEncryption.encrypt(plainText,secretKey, iv)
        println("Enkripsi Text : $encryptedText")

        val decryptedText = AESEncryption.decrypt(encryptedText, secretKey, iv)
        println("Decrypted Text: $decryptedText")
    }

