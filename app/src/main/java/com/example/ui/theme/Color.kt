package com.example.ui.theme

import androidx.compose.ui.graphics.Color

// Nothing OS Signature Palette
val NothingBlack = Color(0xFF000000)        // Pure OLED Black
val NothingDark = Color(0xFF0A0A0A)         // Deep canvas black
val NothingSurface = Color(0xFF141414)      // Widget / Bento Card Surface
val NothingSurfaceVariant = Color(0xFF1C1C1C) // Elevated Tile
val NothingSurfaceElevated = Color(0xFF262626) // Nested Container / Input Field
val NothingBorder = Color(0xFF2C2C2C)       // Subtle 1dp border
val NothingBorderSubtle = Color(0xFF202020)
val NothingBorderActive = Color(0xFF555555)

// Nothing High-Contrast Accents
val NothingWhite = Color(0xFFFFFFFF)        // High contrast primary text & active pills
val NothingGrey = Color(0xFF8E8E93)         // Secondary muted labels
val NothingLightGrey = Color(0xFFCCCCCC)    // Sub-headers
val NothingDimGrey = Color(0xFF48484A)      // Inactive tick / track lines

// Nothing Signature Crimson Red
val NothingRed = Color(0xFFD71921)          // Signature Crimson Red Accent
val NothingRedBright = Color(0xFFFF3B30)
val NothingRedContainer = Color(0xFF26080A)
val NothingRedBorder = Color(0xFF5C1014)

// Nothing Status Semantic Colors
val StatusPhishing = Color(0xFFFF3B30)       // Nothing Crimson Danger
val StatusPhishingOn = Color(0xFF000000)
val StatusPhishingContainer = Color(0xFF2A0D0F)
val StatusPhishingBorder = Color(0xFF6B171B)
val StatusPhishingGlow = Color(0xFFFF3B30)

val StatusSuspicious = Color(0xFFFF9F0A)     // Clean Amber
val StatusSuspiciousOn = Color(0xFF000000)
val StatusSuspiciousContainer = Color(0xFF261904)
val StatusSuspiciousBorder = Color(0xFF5E3904)
val StatusSuspiciousGlow = Color(0xFFFF9F0A)

val StatusSafe = Color(0xFF30D158)           // Clean Emerald Dot
val StatusSafeOn = Color(0xFF000000)
val StatusSafeContainer = Color(0xFF072311)
val StatusSafeBorder = Color(0xFF0F5229)
val StatusSafeGlow = Color(0xFF30D158)

val NothingGreen = StatusSafe
val NothingGreenBorder = StatusSafeBorder
val NothingGreenContainer = StatusSafeContainer
val NothingAmber = StatusSuspicious
val NothingAmberBorder = StatusSuspiciousBorder
val NothingAmberContainer = StatusSuspiciousContainer

// Backwards compatibility tokens
val GeoBackground = NothingBlack
val GeoSurface = NothingSurface
val GeoSurfaceVariant = NothingSurfaceVariant
val GeoSurfaceElevated = NothingSurfaceElevated
val GeoBorder = NothingBorder
val GeoBorderSubtle = NothingBorderSubtle
val GeoPrimary = NothingWhite
val GeoOnPrimary = NothingBlack
val GeoPrimaryContainer = NothingSurfaceElevated
val GeoOnPrimaryContainer = NothingWhite
val GeoSecondary = NothingLightGrey
val GeoSecondaryContainer = NothingSurfaceVariant
val TextPrimary = NothingWhite
val TextSecondary = NothingLightGrey
val TextMuted = NothingGrey
val CyberDarkBackground = NothingBlack
val CyberDarkSurface = NothingSurface
val CyberDarkSurfaceVariant = NothingSurfaceVariant
val CyberCyanPrimary = NothingWhite
val CyberBorder = NothingBorder
