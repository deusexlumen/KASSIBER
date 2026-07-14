package com.kassiber.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val KassiberPrimary = Color(0xFF1B5E20)
private val KassiberSecondary = Color(0xFF0D47A1)
private val KassiberAccent = Color(0xFF00C853)
private val KassiberError = Color(0xFFB71C1C)
private val KassiberSurface = Color(0xFF121212)
private val KassiberSurfaceLight = Color(0xFFF5F5F5)

private val DarkColorScheme = darkColorScheme(
    primary = KassiberPrimary, secondary = KassiberSecondary, tertiary = KassiberAccent,
    error = KassiberError, background = Color.Black, surface = KassiberSurface,
    onPrimary = Color.White, onSecondary = Color.White, onBackground = Color.White, onSurface = Color.White
)

private val LightColorScheme = lightColorScheme(
    primary = KassiberPrimary, secondary = KassiberSecondary, tertiary = KassiberAccent,
    error = KassiberError, background = Color.White, surface = KassiberSurfaceLight,
    onPrimary = Color.White, onSecondary = Color.White, onBackground = Color.Black, onSurface = Color.Black
)

@Composable
fun KassiberTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme, typography = Typography(), content = content)
}
