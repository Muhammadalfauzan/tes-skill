package com.example.tesskillmobilesecurity.deteksitoken

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import java.util.Date

fun tokenValid(token: String, secret: String): Boolean {
    return try {
        val algorithm = Algorithm.HMAC256(secret)
        val verifier = JWT.require(algorithm).build()
        val jwt = verifier.verify(token)

        val expiration = jwt.expiresAt
        val currentTime = Date()

        expiration != null && expiration.after(currentTime)
    } catch (exception: JWTVerificationException) {
        false
    }
}

fun main() {
    val secret = "key secret"

    val token = JWT.create()
        .withIssuer("auth0")
        .withExpiresAt(Date(System.currentTimeMillis() + 10 * 1000))
        .sign(Algorithm.HMAC256(secret))

    println("Generated token: $token")

    // Cek validitas token sebelum kadaluarsa
    val validBeforeSleep = tokenValid(token, secret)
    println("token valid dan belum kadaluarsa $validBeforeSleep")

    // Testing token yang kadarluasa
    Thread.sleep(11000)
    // Cek validitas token setelah kadaluarsa
    val validAfterSleep = tokenValid(token, secret)
    println("token sudah kadaluarsa $validAfterSleep")
}