package com.kassiber.app.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.kassiber.app.ble.BleOnboardingManager
import com.kassiber.app.crypto.CryptoBridge
import com.kassiber.app.ui.theme.KassiberTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var bleManager: BleOnboardingManager

    private val permissionLauncher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
        permissions.entries.forEach { }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        bleManager = BleOnboardingManager(this)
        requestRequiredPermissions()
        setContent {
            KassiberTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    KassiberMainScreen(
                        onEnableAccessibility = { openAccessibilitySettings() },
                        onStartOnboarding = { },
                        bleStatus = bleManager.status.collectAsState().value
                    )
                }
            }
        }
    }

    private fun requestRequiredPermissions() {
        val permissions = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
            permissions.add(Manifest.permission.BLUETOOTH_ADVERTISE)
        } else {
            permissions.add(Manifest.permission.BLUETOOTH)
            permissions.add(Manifest.permission.BLUETOOTH_ADMIN)
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) { permissions.add(Manifest.permission.POST_NOTIFICATIONS) }
        permissions.add(Manifest.permission.CAMERA)
        val needed = permissions.filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        if (needed.isNotEmpty()) permissionLauncher.launch(needed.toTypedArray())
    }

    private fun openAccessibilitySettings() { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }

    override fun onDestroy() { super.onDestroy(); bleManager.stop() }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KassiberMainScreen(onEnableAccessibility: () -> Unit, onStartOnboarding: () -> Unit, bleStatus: BleOnboardingManager.BleStatus) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var cryptoStatus by remember { mutableStateOf("Uninitialized") }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(text = "\uD83D\uDD10 KASSIBER", style = MaterialTheme.typography.headlineLarge, color = MaterialTheme.colorScheme.primary)
        Text(text = "Post-Quantum Secure Messenger Layer", style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        Divider(modifier = Modifier.padding(vertical = 8.dp))

        StatusCard(title = "Crypto Core", status = cryptoStatus, icon = "\uD83D\uDD11")

        val bleText = when (bleStatus) {
            is BleOnboardingManager.BleStatus.Idle -> "Idle"
            is BleOnboardingManager.BleStatus.Advertising -> "Advertising..."
            is BleOnboardingManager.BleStatus.Connecting -> "Connecting..."
            is BleOnboardingManager.BleStatus.Connected -> "Connected: ${bleStatus.address}"
            is BleOnboardingManager.BleStatus.Sending -> "Sending ${bleStatus.current}/${bleStatus.total}"
            is BleOnboardingManager.BleStatus.Completed -> "Transfer Complete"
            is BleOnboardingManager.BleStatus.Error -> "Error: ${bleStatus.message}"
        }
        StatusCard(title = "BLE Onboarding", status = bleText, icon = "\uD83D\uDCF6", isError = bleStatus is BleOnboardingManager.BleStatus.Error)

        Spacer(modifier = Modifier.weight(1f))

        Button(onClick = onEnableAccessibility, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)) {
            Text("\uD83D\uDEE1\uFE0F Enable Accessibility Service")
        }
        Button(onClick = onStartOnboarding, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary)) {
            Text("\uD83D\uDCF8 Scan QR for Pairing")
        }
        OutlinedButton(onClick = { scope.launch { try { cryptoStatus = CryptoBridge().status() } catch (e: Exception) { cryptoStatus = "Error: ${e.message}" } } }, modifier = Modifier.fillMaxWidth()) {
            Text("\uD83D\uDD04 Test Crypto Core")
        }
        Text(text = "AGPL-3.0 | F-Droid Exclusive | No Servers", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(top = 16.dp))
    }
}

@Composable
fun StatusCard(title: String, status: String, icon: String, isError: Boolean = false) {
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = if (isError) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceVariant)) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Column {
                Text(text = "$icon $title", style = MaterialTheme.typography.titleSmall)
                Text(text = status, style = MaterialTheme.typography.bodyMedium, color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
