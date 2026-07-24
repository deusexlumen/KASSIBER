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
    private var scanJob: Job? = null

    companion object {
        val CARRIER_PACKAGES = setOf("com.whatsapp","com.whatsapp.w4b","com.signal","org.thoughtcrime.securesms","com.telegram.messenger","org.telegram.messenger")
        const val PLACEHOLDER_TEXT = "🔐 Entschlüsseln..."
        const val DECRYPT_TIMEOUT_MS = 5000L
        const val SCAN_DEBOUNCE_MS = 300L
        const val REPLY_BUTTON_WIDTH_DP = 140
        const val REPLY_BUTTON_TOP_OFFSET_DP = 40
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

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
                // Debounce: content-changed events arrive in bursts; only the last
                // one within the window triggers a (fresh) screen scan.
                scanJob?.cancel()
                scanJob = serviceScope.launch {
                    delay(SCAN_DEBOUNCE_MS)
                    scanAndProcessScreen(rootInActiveWindow)
                }
            }
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                mainHandler.post { decryptOverlay?.hide(); replyOverlay?.hide() }
            }
        }
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        super.onDestroy()
        scanJob?.cancel()
        serviceScope.cancel()
        decryptOverlay?.destroy()
        replyOverlay?.destroy()
        cryptoBridge?.close()
        cryptoBridge = null
    }

    private suspend fun scanAndProcessScreen(rootNode: AccessibilityNodeInfo?) {
        if (rootNode == null) return
        try {
            // Only the first payload node is processed per scan; further payloads
            // wait for the next scan so a single overlay and a single decrypt
            // timeout stay consistent instead of racing each other.
            val node = findFirstKassiberNode(rootNode) ?: return
            try {
                val bounds = Rect().apply { node.getBoundsInScreen(this) }
                val carrierText = node.text?.toString() ?: return
                mainHandler.post { decryptOverlay?.show(bounds, PLACEHOLDER_TEXT) }
                val result = withTimeoutOrNull(DECRYPT_TIMEOUT_MS) { cryptoBridge?.decryptFromCarrier(carrierText) }
                mainHandler.post {
                    if (result != null) {
                        decryptOverlay?.updateText(String(result, Charsets.UTF_8))
                        showReplyButton(bounds)
                    } else {
                        decryptOverlay?.updateText("❌ Entschlüsselung fehlgeschlagen")
                    }
                }
            } finally {
                node.recycle()
            }
        } finally {
            rootNode.recycle() // root is recycled last, after every child
        }
    }

    // BFS that returns the first node carrying a KASSIBER payload. Traversal
    // nodes that are not returned are recycled immediately; the caller owns the
    // returned node and must recycle it. The root window node itself is never
    // treated as a payload carrier and is recycled by the caller.
    private fun findFirstKassiberNode(root: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        for (i in 0 until root.childCount) root.getChild(i)?.let { queue.addLast(it) }
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            if (CryptoBridge.isKassiberPayload(node.text?.toString() ?: "")) {
                queue.forEach { it.recycle() }
                return node
            }
            for (i in 0 until node.childCount) node.getChild(i)?.let { queue.addLast(it) }
            node.recycle()
        }
        return null
    }

    private fun showReplyButton(messageBounds: Rect) {
        val buttonBounds = Rect(messageBounds.right - dp(REPLY_BUTTON_WIDTH_DP), messageBounds.top - dp(REPLY_BUTTON_TOP_OFFSET_DP), messageBounds.right, messageBounds.top)
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
        try {
            findInputField(root)?.let { inputField ->
                try {
                    inputField.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
                        putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
                    })
                } finally {
                    inputField.recycle()
                }
            }
        } finally {
            root.recycle()
        }
    }

    // Heuristic: the carrier's message entry is an editable, visible field near
    // the bottom of the window. A plain "first EditText" search often hits the
    // search bar at the top instead, so prefer (1) the focused field,
    // (2) otherwise the lowest visible field on screen.
    private fun findInputField(root: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        val candidates = mutableListOf<AccessibilityNodeInfo>()
        collectInputCandidates(root, candidates)
        val visible = candidates.filter { it.isVisibleToUser }.ifEmpty { candidates }
        val chosen = visible.firstOrNull { it.isFocused }
            ?: visible.maxByOrNull { Rect().apply { it.getBoundsInScreen(this) }.top }
        candidates.forEach { if (it !== chosen) it.recycle() }
        return chosen
    }

    private fun collectInputCandidates(root: AccessibilityNodeInfo, out: MutableList<AccessibilityNodeInfo>) {
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        for (i in 0 until root.childCount) root.getChild(i)?.let { queue.addLast(it) }
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            if (node.className?.contains("EditText") == true || node.isEditable || node.viewIdResourceName?.contains("entry") == true || node.viewIdResourceName?.contains("input") == true) {
                out.add(node)
            } else {
                for (i in 0 until node.childCount) node.getChild(i)?.let { queue.addLast(it) }
                node.recycle()
            }
        }
    }
}
