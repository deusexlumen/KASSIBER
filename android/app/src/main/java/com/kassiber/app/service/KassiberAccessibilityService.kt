package com.kassiber.app.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.graphics.Rect
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.kassiber.app.crypto.CryptoBridge
import com.kassiber.app.overlay.DecryptOverlay
import com.kassiber.app.overlay.ReplyOverlay
import kotlinx.coroutines.*
import timber.log.Timber

class KassiberAccessibilityService : AccessibilityService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var decryptOverlay: DecryptOverlay? = null
    private var replyOverlay: ReplyOverlay? = null
    private var cryptoBridge: CryptoBridge? = null

    companion object {
        val CARRIER_PACKAGES = setOf("com.whatsapp","com.whatsapp.w4b","com.signal","org.thoughtcrime.securesms","com.telegram.messenger","org.telegram.messenger")
        const val PLACEHOLDER_TEXT = "\uD83D\uDD10 Entschlüsseln..."
        const val DECRYPT_TIMEOUT_MS = 5000L
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        serviceInfo = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED or AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_VISUAL
            flags = AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
            notificationTimeout = 100
        }
        cryptoBridge = CryptoBridge()
        decryptOverlay = DecryptOverlay(this, getSystemService(WINDOW_SERVICE) as android.view.WindowManager)
        replyOverlay = ReplyOverlay(this, getSystemService(WINDOW_SERVICE) as android.view.WindowManager, cryptoBridge!!)
        Timber.i("KASSIBER AccessibilityService connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg !in CARRIER_PACKAGES) return
        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED, AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                serviceScope.launch { scanAndProcessScreen(rootInActiveWindow) }
            }
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                mainHandler.post { decryptOverlay?.hide(); replyOverlay?.hide() }
            }
        }
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        decryptOverlay?.destroy()
        replyOverlay?.destroy()
    }

    private suspend fun scanAndProcessScreen(rootNode: AccessibilityNodeInfo?) {
        if (rootNode == null) return
        for (node in findKassiberNodes(rootNode)) {
            val bounds = Rect().apply { node.getBoundsInScreen(this) }
            val carrierText = node.text?.toString() ?: continue
            mainHandler.post { decryptOverlay?.show(bounds, PLACEHOLDER_TEXT) }
            val result = withTimeoutOrNull(DECRYPT_TIMEOUT_MS) { cryptoBridge?.decryptFromCarrier(carrierText) }
            mainHandler.post {
                if (result != null) {
                    decryptOverlay?.updateText(String(result, Charsets.UTF_8))
                    showReplyButton(bounds)
                } else {
                    decryptOverlay?.updateText("\u274C Entschlüsselung fehlgeschlagen")
                }
            }
        }
        rootNode.recycle()
    }

    private fun findKassiberNodes(root: AccessibilityNodeInfo): List<AccessibilityNodeInfo> {
        val results = mutableListOf<AccessibilityNodeInfo>()
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            if (CryptoBridge.isKassiberPayload(node.text?.toString() ?: "")) results.add(node)
            for (i in 0 until node.childCount) node.getChild(i)?.let { queue.add(it) }
        }
        return results
    }

    private fun showReplyButton(messageBounds: Rect) {
        val buttonBounds = Rect(messageBounds.right - 200, messageBounds.top - 80, messageBounds.right, messageBounds.top)
        replyOverlay?.showReplyButton(buttonBounds) { onReplyClicked(messageBounds) }
    }

    private fun onReplyClicked(messageBounds: Rect) {
        replyOverlay?.showComposeDialog(messageBounds) { plaintext ->
            serviceScope.launch { encryptAndInject(plaintext) }
        }
    }

    private suspend fun encryptAndInject(plaintext: String) {
        try {
            val carrierText = cryptoBridge?.encryptForCarrier(plaintext.toByteArray(Charsets.UTF_8)) ?: return
            mainHandler.post { injectTextIntoCarrierInput(carrierText) }
        } catch (e: Exception) { Timber.e(e, "Encryption/Injection failed") }
    }

    private fun injectTextIntoCarrierInput(text: String) {
        val root = rootInActiveWindow ?: return
        findInputField(root)?.let { inputField ->
            inputField.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
            })
            inputField.recycle()
        }
        root.recycle()
    }

    private fun findInputField(root: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            if (node.className?.contains("EditText") == true || node.isEditable || node.viewIdResourceName?.contains("entry") == true || node.viewIdResourceName?.contains("input") == true) return node
            for (i in 0 until node.childCount) node.getChild(i)?.let { queue.add(it) }
        }
        return null
    }
}
