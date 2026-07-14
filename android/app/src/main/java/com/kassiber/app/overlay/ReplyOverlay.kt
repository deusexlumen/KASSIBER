package com.kassiber.app.overlay

import android.content.Context
import android.graphics.PixelFormat
import android.graphics.Rect
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import com.kassiber.app.R
import com.kassiber.app.crypto.CryptoBridge
import timber.log.Timber

class ReplyOverlay(private val context: Context, private val windowManager: WindowManager, private val cryptoBridge: CryptoBridge) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private var replyButtonView: View? = null
    private var composeView: View? = null

    fun showReplyButton(bounds: Rect, onClick: () -> Unit) {
        hideReplyButton()
        mainHandler.post {
            try {
                val button = Button(context).apply {
                    text = "\uD83D\uDD11 Antworten"
                    setBackgroundColor(context.getColor(R.color.kassiber_accent))
                    setTextColor(context.getColor(android.R.color.white))
                    setOnClickListener { hideReplyButton(); onClick() }
                }
                replyButtonView = button
                windowManager.addView(button, WindowManager.LayoutParams(bounds.width(), 120, bounds.left, bounds.top,
                    WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY, WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE, PixelFormat.TRANSLUCENT).apply { gravity = Gravity.TOP or Gravity.START })
            } catch (e: Exception) { Timber.e(e, "Failed to show reply button") }
        }
    }

    fun showComposeDialog(nearBounds: Rect, onSend: (String) -> Unit) {
        hideComposeDialog()
        mainHandler.post {
            try {
                val editText = EditText(context).apply { hint = "KASSIBER-Antwort..."; setTextColor(context.getColor(R.color.kassiber_text_primary)); minLines = 3; maxLines = 6 }
                val layout = LinearLayout(context).apply {
                    orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 24)
                    setBackgroundColor(context.getColor(R.color.kassiber_surface))
                    addView(editText)
                    addView(Button(context).apply {
                        text = "\uD83D\uDD10 Verschlüsseln & Senden"
                        setBackgroundColor(context.getColor(R.color.kassiber_accent))
                        setOnClickListener { val text = editText.text.toString(); if (text.isNotBlank()) { hideComposeDialog(); onSend(text) } }
                    })
                }
                composeView = layout
                windowManager.addView(layout, WindowManager.LayoutParams(nearBounds.width() + 100, WindowManager.LayoutParams.WRAP_CONTENT, nearBounds.left - 50, nearBounds.top - 200,
                    WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY, WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL, PixelFormat.TRANSLUCENT).apply { gravity = Gravity.TOP or Gravity.START })
                editText.requestFocus()
            } catch (e: Exception) { Timber.e(e, "Failed to show compose dialog") }
        }
    }

    fun hideReplyButton() { mainHandler.post { try { replyButtonView?.let { windowManager.removeView(it); replyButtonView = null } } catch (_: IllegalArgumentException) {} } }
    fun hideComposeDialog() { mainHandler.post { try { composeView?.let { windowManager.removeView(it); composeView = null } } catch (_: IllegalArgumentException) {} } }
    fun hide() { hideReplyButton(); hideComposeDialog() }
    fun destroy() { hide() }
}
