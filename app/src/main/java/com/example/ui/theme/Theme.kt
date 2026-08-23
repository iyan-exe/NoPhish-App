package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val NothingDarkColorScheme = darkColorScheme(
    primary = NothingWhite,
    onPrimary = NothingBlack,
    primaryContainer = NothingSurfaceElevated,
    onPrimaryContainer = NothingWhite,
    secondary = NothingLightGrey,
    onSecondary = NothingBlack,
    secondaryContainer = NothingSurfaceVariant,
    onSecondaryContainer = NothingWhite,
    tertiary = NothingRed,
    background = NothingBlack,
    onBackground = NothingWhite,
    surface = NothingSurface,
    onSurface = NothingWhite,
    surfaceVariant = NothingSurfaceVariant,
    onSurfaceVariant = NothingGrey,
    outline = NothingBorder,
    outlineVariant = NothingBorderSubtle,
    error = StatusPhishing,
    errorContainer = StatusPhishingContainer,
    onError = NothingBlack,
    onErrorContainer = StatusPhishing
)

private val NothingLightColorScheme = lightColorScheme(
    primary = NothingBlack,
    onPrimary = NothingWhite,
    primaryContainer = Color(0xFFF0F0F0),
    onPrimaryContainer = NothingBlack,
    secondary = Color(0xFF444444),
    onSecondary = NothingWhite,
    secondaryContainer = Color(0xFFE5E5E5),
    onSecondaryContainer = NothingBlack,
    tertiary = NothingRed,
    background = Color(0xFFF7F7F8),
    onBackground = NothingBlack,
    surface = Color(0xFFFFFFFF),
    onSurface = NothingBlack,
    surfaceVariant = Color(0xFFEAEAEA),
    onSurfaceVariant = Color(0xFF666666),
    outline = Color(0xFFCCCCCC),
    outlineVariant = Color(0xFFE0E0E0),
    error = NothingRed,
    errorContainer = Color(0xFFFFECEC),
    onError = NothingWhite,
    onErrorContainer = NothingRed
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true, // Default to Nothing OS Dark
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) NothingDarkColorScheme else NothingLightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
