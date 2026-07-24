package com.kassiber.app.crypto

import com.kassiber.ffi.KassiberFfiException
import com.kassiber.ffi.KassiberIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.Closeable

/**
 * Thin facade over the generated UniFFI bindings (`com.kassiber.ffi`).
 *
 * Owns a single [KassiberIdentity] (keypairs + one peer session). The session
 * is established during onboarding via [exportPrekeyBundle] /
 * [initiateSession] / [acceptSession]; until then every messaging call fails
 * with a controlled [KassiberFfiException.SessionNotEstablished] (encrypt) or
 * `null` (decrypt) instead of crashing.
 *
 * If the native library (`libkassiber_ffi.so`) is missing — e.g. the NDK build
 * has not run yet — the identity stays `null` and all calls fail the same
 * controlled way; the app itself keeps running.
 */
class CryptoBridge : Closeable {

    companion object {
        const val KASSIBER_MARKER = "<<<KASSIBER>>>"

        /** Marker check only — never touches the native session state. */
        fun isKassiberPayload(text: String): Boolean = text.contains(KASSIBER_MARKER)
    }

    private var identity: KassiberIdentity? = try {
        KassiberIdentity.create()
    } catch (t: Throwable) {
        // UnsatisfiedLinkError (no .so) or native init failure: degrade, don't crash.
        Timber.w(t, "Native crypto core unavailable")
        null
    }

    private fun identityOrThrow(): KassiberIdentity =
        identity ?: throw KassiberFfiException.Internal("native crypto core unavailable (libkassiber_ffi not loaded)")

    // --- Onboarding (BLE/QR pairing) ---

    /** Our signed prekey bundle, to be published to the peer. */
    suspend fun exportPrekeyBundle(): ByteArray = withContext(Dispatchers.IO) {
        identityOrThrow().exportPrekeyBundle()
    }

    /** Initiator side: consume the peer's bundle, return the handshake message. */
    suspend fun initiateSession(peerBundle: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        identityOrThrow().initiateSession(peerBundle)
    }

    /** Responder side: complete the session with the peer's handshake message. */
    suspend fun acceptSession(handshake: ByteArray): Unit = withContext(Dispatchers.IO) {
        identityOrThrow().acceptSession(handshake)
    }

    fun hasSession(): Boolean = identity?.isSessionEstablished() ?: false

    // --- Messaging ---

    /**
     * Real session encryption (ratcheted AES-256-GCM) plus carrier encoding
     * with the KASSIBER marker. Throws [KassiberFfiException] when no session
     * is established yet.
     */
    suspend fun encryptForCarrier(plaintext: ByteArray): String = withContext(Dispatchers.IO) {
        identityOrThrow().encryptForCarrier(plaintext)
    }

    /**
     * Returns the decrypted plaintext, or `null` when the text carries no
     * KASSIBER payload or decoding/decryption fails — the caller renders that
     * as "decryption failed" instead of crashing.
     */
    suspend fun decryptFromCarrier(carrierText: String): ByteArray? = withContext(Dispatchers.IO) {
        try {
            identityOrThrow().decryptFromCarrier(carrierText)
        } catch (e: KassiberFfiException) {
            Timber.w(e, "decryptFromCarrier failed")
            null
        }
    }

    fun status(): String = when {
        identity == null -> "native core unavailable"
        hasSession() -> "session established"
        else -> "identity ready, no session"
    }

    // Releases the native identity; call when the owner (activity/service) is destroyed.
    override fun close() {
        identity?.close()
        identity = null
    }
}
