package com.kassiber.app.ble

import android.content.Context
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.util.concurrent.Executors

class QrScanner(private val context: Context) {

    private val executor = Executors.newSingleThreadExecutor()
    private val barcodeScanner = BarcodeScanning.getClient()
    private val _scanResult = MutableSharedFlow<ScanResult>()
    val scanResult = _scanResult.asSharedFlow()

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
        val mediaImage = imageProxy.image ?: run { imageProxy.close(); return }
        val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
        barcodeScanner.process(image)
            .addOnSuccessListener { barcodes -> barcodes.forEach { processBarcode(it) } }
            .addOnCompleteListener { imageProxy.close() }
    }

    private fun processBarcode(barcode: Barcode) {
        val rawValue = barcode.rawValue ?: return
        try {
            val result = parseBootstrapToken(rawValue)
            CoroutineScope(Dispatchers.Main).launch { _scanResult.emit(result) }
            Timber.i("QR-Code erkannt: MAC=${result.bleMacAddress}")
        } catch (e: Exception) { Timber.d("Invalid QR-Code: ${e.message}") }
    }

    private fun parseBootstrapToken(rawValue: String): ScanResult {
        val decoded = android.util.Base64.decode(rawValue, android.util.Base64.URL_SAFE)
        if (decoded.size < 38) throw IllegalArgumentException("Bootstrap token too short")
        val x25519Pubkey = decoded.sliceArray(0 until 32)
        val macBytes = decoded.sliceArray(32 until 38)
        val macAddress = macBytes.joinToString(":") { "%02X".format(it) }
        return ScanResult(x25519Pubkey, macAddress, rawValue)
    }

    fun stop() { executor.shutdown(); Timber.d("QR-Scanner stopped") }
}
