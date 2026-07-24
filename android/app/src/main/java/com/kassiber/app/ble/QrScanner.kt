package com.kassiber.app.ble

import android.content.Context
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.util.concurrent.Executors

class QrScanner(private val context: Context) {

    private val executor = Executors.newSingleThreadExecutor()
    private val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }
    private val _scanResult = MutableSharedFlow<ScanResult>()
    val scanResult = _scanResult.asSharedFlow()

    companion object {
        // Bootstrap token wire format: version(1) || x25519 pubkey(32) || BLE MAC(6)
        const val TOKEN_VERSION: Byte = 0x01
        const val TOKEN_LENGTH = 39
        const val PUBKEY_LENGTH = 32
        const val MAC_LENGTH = 6
    }

    data class ScanResult(val x25519Pubkey: ByteArray, val bleMacAddress: String, val rawData: String) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ScanResult) return false
            return x25519Pubkey.contentEquals(other.x25519Pubkey) && bleMacAddress == other.bleMacAddress
        }
        override fun hashCode(): Int = 31 * x25519Pubkey.contentHashCode() + bleMacAddress.hashCode()
    }

    fun startScanning(lifecycleOwner: LifecycleOwner, previewView: PreviewView) {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        cameraProviderFuture.addListener({
            try {
                val cameraProvider = cameraProviderFuture.get()
                val preview = Preview.Builder().build().apply { setSurfaceProvider(previewView.surfaceProvider) }
                val imageAnalysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build().apply {
                    setAnalyzer(executor) { imageProxy -> processImage(imageProxy) }
                }
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, imageAnalysis)
            } catch (e: Exception) { Timber.e(e, "Failed to start QR-Scanner") }
        }, ContextCompat.getMainExecutor(context))
    }

    private fun processImage(imageProxy: ImageProxy) {
        try {
            val text = decodeQr(imageProxy)
            if (text != null) processCode(text)
        } finally {
            imageProxy.close()
        }
    }

    private fun decodeQr(imageProxy: ImageProxy): String? {
        // CameraX delivers YUV_420_888; plane 0 is the luminance (Y) channel ZXing needs.
        val plane = imageProxy.planes[0]
        if (plane.pixelStride != 1) return null // unsupported layout, skip frame
        val buffer = plane.buffer
        val data = ByteArray(buffer.remaining())
        buffer.get(data)
        val source = PlanarYUVLuminanceSource(data, plane.rowStride, imageProxy.height, 0, 0, imageProxy.width, imageProxy.height, false)
        return try {
            reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
        } catch (e: NotFoundException) {
            null
        } finally {
            reader.reset()
        }
    }

    private fun processCode(rawValue: String) {
        try {
            val result = parseBootstrapToken(rawValue)
            CoroutineScope(Dispatchers.Main).launch { _scanResult.emit(result) }
            Timber.i("QR-Code erkannt: MAC=${result.bleMacAddress}")
        } catch (e: Exception) {
            Timber.w("Ignoring invalid bootstrap QR-Code: ${e.message}")
        }
    }

    private fun parseBootstrapToken(rawValue: String): ScanResult {
        val decoded = try {
            android.util.Base64.decode(rawValue, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Token is not valid base64url")
        }
        if (decoded.size != TOKEN_LENGTH) throw IllegalArgumentException("Bootstrap token must be $TOKEN_LENGTH bytes, got ${decoded.size}")
        if (decoded[0] != TOKEN_VERSION) throw IllegalArgumentException("Unsupported bootstrap token version ${decoded[0]}")
        val x25519Pubkey = decoded.sliceArray(1 until 1 + PUBKEY_LENGTH)
        val macBytes = decoded.sliceArray(1 + PUBKEY_LENGTH until TOKEN_LENGTH)
        if (macBytes.all { it == 0.toByte() } || macBytes.all { it == 0xFF.toByte() }) {
            throw IllegalArgumentException("Invalid BLE MAC address in token")
        }
        val macAddress = macBytes.joinToString(":") { "%02X".format(it) }
        return ScanResult(x25519Pubkey, macAddress, rawValue)
    }

    fun stop() { executor.shutdown(); Timber.d("QR-Scanner stopped") }
}
