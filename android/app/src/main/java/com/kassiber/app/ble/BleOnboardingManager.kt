package com.kassiber.app.ble

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import timber.log.Timber
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class BleOnboardingManager(private val context: Context) {

    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager.adapter
    private var gattServer: BluetoothGattServer? = null
    private var gattClient: BluetoothGatt? = null
    private var advertiseCallback: AdvertiseCallback? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _status = MutableStateFlow<BleStatus>(BleStatus.Idle)
    val status: StateFlow<BleStatus> = _status.asStateFlow()

    private val _receivedBundle = Channel<ByteArray>(Channel.BUFFERED)
    val receivedBundle = _receivedBundle.receiveAsFlow()

    companion object {
        val KASSIBER_SERVICE_UUID: UUID = UUID.fromString("550e8400-e29b-41d4-a716-446655440000")
        val PQC_BUNDLE_UUID: UUID = UUID.fromString("550e8400-e29b-41d4-a716-446655440001")
        val STATUS_UUID: UUID = UUID.fromString("550e8400-e29b-41d4-a716-446655440002")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        const val MTU_SIZE = 512
        const val DEFAULT_MTU = 23
        const val GATT_ATT_OVERHEAD = 3 // ATT opcode + handle bytes per write
        const val GCM_TAG_BITS = 128
        const val GCM_NONCE_BYTES = 12
        const val X25519_KEY_BYTES = 32
        val HKDF_INFO = "kassiber-ble-bundle-v1".toByteArray(Charsets.UTF_8)
    }

    // Payload chunk size derived from the negotiated MTU; falls back to the
    // mandatory 23-byte ATT MTU until onMtuChanged reports otherwise.
    @Volatile private var chunkSize = DEFAULT_MTU - GATT_ATT_OVERHEAD

    @SuppressLint("MissingPermission") // guarded by hasBlePermissions()
    fun startGattServer() {
        if (adapter == null) { _status.value = BleStatus.Error("Bluetooth not available"); return }
        if (!hasBlePermissions()) { _status.value = BleStatus.Error("Missing BLE permissions"); return }
        val callback = object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> { Timber.i("BLE client connected: ${device.address}"); _status.value = BleStatus.Connected(device.address) }
                    BluetoothProfile.STATE_DISCONNECTED -> { Timber.i("BLE client disconnected"); _status.value = BleStatus.Idle }
                }
            }
            override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) {
                if (characteristic.uuid == PQC_BUNDLE_UUID) {
                    scope.launch { _receivedBundle.send(value) }
                    if (responseNeeded) gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                }
            }
        }
        try {
            gattServer = bluetoothManager.openGattServer(context, callback)
        } catch (e: SecurityException) {
            _status.value = BleStatus.Error("Permission denied for GATT server"); return
        }
        val service = BluetoothGattService(KASSIBER_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        // Encrypted permissions require an encrypted (bonded) link, so bundle
        // bytes are never readable/writable on a plain unencrypted connection.
        service.addCharacteristic(BluetoothGattCharacteristic(PQC_BUNDLE_UUID, BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE, BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED).apply { writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT })
        service.addCharacteristic(BluetoothGattCharacteristic(STATUS_UUID, BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY, BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED))
        try {
            gattServer?.addService(service)
        } catch (e: SecurityException) {
            _status.value = BleStatus.Error("Permission denied for GATT service"); return
        }
        _status.value = BleStatus.Advertising
        startAdvertising()
        Timber.i("GATT-Server started")
    }

    @SuppressLint("MissingPermission") // guarded by hasBlePermissions()
    private fun startAdvertising() {
        val settings = AdvertiseSettings.Builder().setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).setConnectable(true).setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH).build()
        val data = AdvertiseData.Builder().setIncludeDeviceName(false).addServiceUuid(ParcelUuid(KASSIBER_SERVICE_UUID)).build()
        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) { Timber.i("BLE advertising started") }
            override fun onStartFailure(errorCode: Int) { Timber.e("BLE advertising failed: $errorCode"); _status.value = BleStatus.Error("Advertising failed: $errorCode") }
        }
        try {
            adapter?.bluetoothLeAdvertiser?.startAdvertising(settings, data, callback)
            advertiseCallback = callback // keep reference so stop() can halt advertising
        } catch (e: SecurityException) { _status.value = BleStatus.Error("Permission denied for advertising") }
    }

    @SuppressLint("MissingPermission") // guarded by hasBlePermissions()
    fun connectAndSendBundle(deviceAddress: String, bundleData: ByteArray, peerX25519Pubkey: ByteArray) {
        if (adapter == null || !hasBlePermissions()) { _status.value = BleStatus.Error("Bluetooth unavailable"); return }
        val sealed = try {
            sealBundle(bundleData, peerX25519Pubkey)
        } catch (e: Exception) {
            Timber.e(e, "Failed to seal bundle"); _status.value = BleStatus.Error("Bundle encryption failed"); return
        }
        chunkSize = DEFAULT_MTU - GATT_ATT_OVERHEAD // reset until MTU negotiation completes
        val device = adapter.getRemoteDevice(deviceAddress)
        val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> { gatt.requestMtu(MTU_SIZE) }
                    BluetoothProfile.STATE_DISCONNECTED -> { _status.value = BleStatus.Idle }
                }
            }
            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    chunkSize = (mtu - GATT_ATT_OVERHEAD).coerceAtLeast(DEFAULT_MTU - GATT_ATT_OVERHEAD)
                    Timber.i("Negotiated MTU $mtu, chunk size $chunkSize")
                    gatt.discoverServices()
                }
            }
            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) { if (status == BluetoothGatt.GATT_SUCCESS) scope.launch { sendBundleChunks(gatt, sealed) } }
        }
        _status.value = BleStatus.Connecting
        try {
            gattClient = device.connectGatt(context, false, callback)
        } catch (e: SecurityException) { _status.value = BleStatus.Error("Permission denied for GATT connect") }
    }

    // Bind the bundle to the peer scanned from the QR code: an ephemeral X25519
    // keypair is combined with the peer's static pubkey, the shared secret is
    // stretched via HKDF-SHA256 (RFC 5869) and the bundle is sealed with
    // AES-128-GCM. Wire format: ephemeralPub(32) || nonce(12) || ciphertext||tag.
    // Only the holder of the private key matching the QR pubkey can open it.
    private fun sealBundle(bundleData: ByteArray, peerX25519Pubkey: ByteArray): ByteArray {
        require(peerX25519Pubkey.size == X25519_KEY_BYTES) { "Invalid peer X25519 pubkey length" }
        val random = SecureRandom()
        val ephemeralPrivate = X25519PrivateKeyParameters(random)
        val ephemeralPublic = ephemeralPrivate.generatePublicKey()
        val agreement = X25519Agreement()
        agreement.init(ephemeralPrivate)
        val sharedSecret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerX25519Pubkey, 0), sharedSecret, 0)
        val key = hkdfSha256(salt = null, ikm = sharedSecret, info = HKDF_INFO, length = 16)
        val nonce = ByteArray(GCM_NONCE_BYTES).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        val ciphertext = cipher.doFinal(bundleData)
        return ephemeralPublic.encoded + nonce + ciphertext
    }

    // RFC 5869 HKDF with HMAC-SHA256 (extract + expand).
    private fun hkdfSha256(salt: ByteArray?, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt ?: ByteArray(32), "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val okm = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.reset()
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val take = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, okm, offset, take)
            offset += take
            counter++
        }
        return okm
    }

    @SuppressLint("MissingPermission") // permission checked by caller
    private suspend fun sendBundleChunks(gatt: BluetoothGatt, bundleData: ByteArray) {
        val service = gatt.getService(KASSIBER_SERVICE_UUID) ?: return
        val characteristic = service.getCharacteristic(PQC_BUNDLE_UUID) ?: return
        val chunks = bundleData.asList().chunked(chunkSize)
        Timber.i("Sending ${chunks.size} chunks (${bundleData.size} bytes)")
        for ((index, chunk) in chunks.withIndex()) {
            characteristic.value = chunk.toByteArray()
            try { gatt.writeCharacteristic(characteristic) } catch (e: SecurityException) { return }
            delay(50)
            _status.value = BleStatus.Sending(index + 1, chunks.size)
        }
        _status.value = BleStatus.Completed
    }

    private fun hasBlePermissions(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED && context.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
        } else {
            context.checkSelfPermission(Manifest.permission.BLUETOOTH) == PackageManager.PERMISSION_GRANTED && context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        }
    }

    @SuppressLint("MissingPermission") // stopping is safe regardless; SDK still throws on S+
    fun stop() {
        try {
            advertiseCallback?.let { callback ->
                try { adapter?.bluetoothLeAdvertiser?.stopAdvertising(callback) } catch (e: SecurityException) { Timber.w("No permission to stop advertising") }
            }
            gattServer?.close()
            gattClient?.disconnect()
            gattClient?.close()
        } catch (e: Exception) { Timber.e(e, "BLE cleanup error") }
        advertiseCallback = null
        gattServer = null
        gattClient = null
        scope.cancel()
        _status.value = BleStatus.Idle
    }

    sealed class BleStatus {
        object Idle : BleStatus()
        object Advertising : BleStatus()
        object Connecting : BleStatus()
        data class Connected(val address: String) : BleStatus()
        data class Sending(val current: Int, val total: Int) : BleStatus()
        object Completed : BleStatus()
        data class Error(val message: String) : BleStatus()
    }
}
