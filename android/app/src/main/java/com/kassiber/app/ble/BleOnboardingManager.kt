package com.kassiber.app.ble

import android.Manifest
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import androidx.core.app.ActivityCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.util.*

class BleOnboardingManager(private val context: Context) {

    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager.adapter
    private var gattServer: BluetoothGattServer? = null
    private var gattClient: BluetoothGatt? = null
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
        const val BUNDLE_CHUNK_SIZE = 500
    }

    fun startGattServer() {
        if (adapter == null) { _status.value = BleStatus.Error("Bluetooth not available"); return }
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
        gattServer = bluetoothManager.openGattServer(context, callback)
        val service = BluetoothGattService(KASSIBER_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(BluetoothGattCharacteristic(PQC_BUNDLE_UUID, BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE, BluetoothGattCharacteristic.PERMISSION_WRITE).apply { writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT })
        service.addCharacteristic(BluetoothGattCharacteristic(STATUS_UUID, BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY, BluetoothGattCharacteristic.PERMISSION_READ))
        gattServer?.addService(service)
        _status.value = BleStatus.Advertising
        startAdvertising()
        Timber.i("GATT-Server started")
    }

    private fun startAdvertising() {
        if (!hasBlePermissions()) { _status.value = BleStatus.Error("Missing BLE permissions"); return }
        val settings = AdvertiseSettings.Builder().setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).setConnectable(true).setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH).build()
        val data = AdvertiseData.Builder().setIncludeDeviceName(false).addServiceUuid(ParcelUuid(KASSIBER_SERVICE_UUID)).build()
        try { adapter?.bluetoothLeAdvertiser?.startAdvertising(settings, data, object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) { Timber.i("BLE advertising started") }
            override fun onStartFailure(errorCode: Int) { Timber.e("BLE advertising failed: $errorCode"); _status.value = BleStatus.Error("Advertising failed: $errorCode") }
        }) } catch (e: SecurityException) { _status.value = BleStatus.Error("Permission denied for advertising") }
    }

    fun connectAndSendBundle(deviceAddress: String, bundleData: ByteArray) {
        if (adapter == null || !hasBlePermissions()) { _status.value = BleStatus.Error("Bluetooth unavailable"); return }
        val device = adapter.getRemoteDevice(deviceAddress)
        val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> { gatt.requestMtu(MTU_SIZE) }
                    BluetoothProfile.STATE_DISCONNECTED -> { _status.value = BleStatus.Idle }
                }
            }
            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) { if (status == BluetoothGatt.GATT_SUCCESS) gatt.discoverServices() }
            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) { if (status == BluetoothGatt.GATT_SUCCESS) scope.launch { sendBundleChunks(gatt, bundleData) } }
        }
        _status.value = BleStatus.Connecting
        gattClient = device.connectGatt(context, false, callback)
    }

    private suspend fun sendBundleChunks(gatt: BluetoothGatt, bundleData: ByteArray) {
        val service = gatt.getService(KASSIBER_SERVICE_UUID) ?: return
        val characteristic = service.getCharacteristic(PQC_BUNDLE_UUID) ?: return
        val chunks = bundleData.asList().chunked(BUNDLE_CHUNK_SIZE)
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

    fun stop() {
        try { gattServer?.close(); gattClient?.disconnect(); gattClient?.close() } catch (e: Exception) { Timber.e(e, "BLE cleanup error") }
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
