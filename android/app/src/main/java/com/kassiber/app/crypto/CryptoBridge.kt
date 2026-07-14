package com.kassiber.app.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class CryptoBridge {
    companion object {
        const val KASSIBER_MARKER = "<<<KASSIBER>>>"

        @JvmStatic external fun nativeCreateHandle(): Long
        @JvmStatic external fun nativeDestroyHandle(handle: Long)
        @JvmStatic external fun nativeInitialize(handle: Long)
        @JvmStatic external fun nativeEncryptForCarrier(handle: Long, plaintext: ByteArray): String
        @JvmStatic external fun nativeDecryptFromCarrier(handle: Long, carrierText: String): ByteArray
        @JvmStatic external fun nativeDetectKassiber(handle: Long, text: String): Boolean
        @JvmStatic external fun nativeStatus(handle: Long): String

        fun isKassiberPayload(text: String): Boolean = text.contains(KASSIBER_MARKER)
    }

    private var handle: Long = nativeCreateHandle()

    init { nativeInitialize(handle) }

    suspend fun encryptForCarrier(plaintext: ByteArray): String = withContext(Dispatchers.IO) {
        nativeEncryptForCarrier(handle, plaintext)
    }

    suspend fun decryptFromCarrier(carrierText: String): ByteArray = withContext(Dispatchers.IO) {
        nativeDecryptFromCarrier(handle, carrierText)
    }

    fun status(): String = nativeStatus(handle)
}
