package com.kassiber.app.overlay

import android.content.Context
import android.graphics.PixelFormat
import android.graphics.Rect
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import androidx.cardview.widget.CardView
import com.kassiber.app.R
import timber.log.Timber

class DecryptOverlay(private val context: Context, private val windowManager: WindowManager) {
    private var overlayView: View? = null
    private var textView: TextView? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    private fun dp(value: Float): Float = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value, context.resources.displayMetrics)

    fun show(bounds: Rect, initialText: String) {
        hide()
        mainHandler.post {
            try {
                val card = CardView(context).apply {
                    radius = dp(12f); cardElevation = dp(8f)
                    setCardBackgroundColor(context.getColor(R.color.kassiber_overlay_bg))
                    alpha = 0.95f
                    addView(TextView(context).apply {
                        id = R.id.overlay_text
                        text = initialText
                        setTextColor(context.getColor(R.color.kassiber_text_primary))
                        textSize = 14f
                        val hPad = dp(16f).toInt(); val vPad = dp(12f).toInt()
                        setPadding(hPad, vPad, hPad, vPad)
                    })
                }
                val view = android.widget.FrameLayout(context).apply {
                    layoutParams = android.widget.FrameLayout.LayoutParams(bounds.width(), android.widget.FrameLayout.LayoutParams.WRAP_CONTENT)
                    addView(card)
                }
                overlayView = view
                textView = view.findViewById(R.id.overlay_text)
                windowManager.addView(view, WindowManager.LayoutParams(bounds.width(), WindowManager.LayoutParams.WRAP_CONTENT, bounds.left, bounds.top,
                    WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                    // Read-only overlay: touches must pass through to the carrier app.
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
                    PixelFormat.TRANSLUCENT).apply { gravity = Gravity.TOP or Gravity.START })
            } catch (e: Exception) { Timber.e(e, "Failed to show decrypt overlay") }
        }
    }

    fun updateText(text: String) { mainHandler.post { textView?.text = text; textView?.visibility = View.VISIBLE } }

    fun hide() { mainHandler.post { try { overlayView?.let { windowManager.removeView(it); overlayView = null; textView = null } } catch (_: IllegalArgumentException) {} } }
    fun destroy() { hide() }
}
