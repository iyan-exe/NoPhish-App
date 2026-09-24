package com.example.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.NothingBlack
import com.example.ui.theme.NothingBorder
import com.example.ui.theme.NothingGrey
import com.example.ui.theme.NothingRed
import com.example.ui.theme.NothingSurface
import com.example.ui.theme.NothingWhite
import com.example.ui.theme.StatusPhishing
import com.example.ui.theme.StatusPhishingBorder
import com.example.ui.theme.StatusPhishingContainer
import com.example.ui.theme.StatusSafe
import com.example.ui.theme.StatusSafeBorder
import com.example.ui.theme.StatusSafeContainer
import com.example.ui.theme.StatusSuspicious
import com.example.ui.theme.StatusSuspiciousBorder
import com.example.ui.theme.StatusSuspiciousContainer
import kotlin.math.cos
import kotlin.math.sin

/**
 * Nothing OS Minimalist Circular Glyph Dial.
 * Features segmented tick perimeter, clean high-contrast monospace score, and red/amber/green accent.
 * Tuned with 120Hz smooth physics interpolation.
 */
@Composable
fun RiskScoreGauge(
    score: Int,
    status: String,
    modifier: Modifier = Modifier
) {
    val animatedProgress = remember { Animatable(0f) }
    val dialScale = remember { Animatable(0.92f) }

    LaunchedEffect(score) {
        animatedProgress.snapTo(0f)
        dialScale.snapTo(0.92f)
        
        // 120Hz smooth cubic easing & spring interpolation
        dialScale.animateTo(
            targetValue = 1f,
            animationSpec = spring(
                dampingRatio = Spring.DampingRatioMediumBouncy,
                stiffness = Spring.StiffnessLow
            )
        )
    }

    LaunchedEffect(score) {
        animatedProgress.animateTo(
            targetValue = score / 100f,
            animationSpec = tween(
                durationMillis = 850,
                easing = CubicBezierEasing(0.16f, 1f, 0.3f, 1f) // Ultra-smooth 120Hz ease-out
            )
        )
    }

    val (statusColor, pillBg, pillBorder, statusLabel, glyphSymbol) = when {
        status.contains("BLOCK", ignoreCase = true) ->
            Tuple5(StatusPhishing, StatusPhishingContainer, StatusPhishingBorder, "BLOCKED", "✖")
        score >= 76 || status.contains("LIKELY", ignoreCase = true) || (status.contains("PHISH", ignoreCase = true) && !status.contains("LOW", ignoreCase = true)) ->
            Tuple5(StatusPhishing, StatusPhishingContainer, StatusPhishingBorder, "LIKELY PHISHING", "▲")
        score >= 51 || status.contains("HIGH", ignoreCase = true) ->
            Tuple5(StatusPhishing, StatusPhishingContainer, StatusPhishingBorder, "HIGH RISK", "▲")
        score >= 21 || status.contains("SUSP", ignoreCase = true) ->
            Tuple5(StatusSuspicious, StatusSuspiciousContainer, StatusSuspiciousBorder, "SUSPICIOUS", "◆")
        else ->
            Tuple5(StatusSafe, StatusSafeContainer, StatusSafeBorder, "LOW RISK", "●")
    }

    Column(
        modifier = modifier.scale(dialScale.value),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier.size(170.dp),
            contentAlignment = Alignment.Center
        ) {
            // Nothing OS Segmented Tick Ring
            Canvas(modifier = Modifier.size(160.dp)) {
                val center = Offset(size.width / 2, size.height / 2)
                val outerRadius = size.minDimension / 2 - 4.dp.toPx()
                val innerRadius = outerRadius - 10.dp.toPx()
                val totalTicks = 48
                val activeTicks = (totalTicks * animatedProgress.value).toInt()

                // Draw 48 tick lines around the perimeter (Nothing OS Clock/Dial Style)
                for (i in 0 until totalTicks) {
                    val angleDeg = -90f + (i * (360f / totalTicks))
                    val angleRad = Math.toRadians(angleDeg.toDouble())

                    val startX = (center.x + innerRadius * cos(angleRad)).toFloat()
                    val startY = (center.y + innerRadius * sin(angleRad)).toFloat()
                    val endX = (center.x + outerRadius * cos(angleRad)).toFloat()
                    val endY = (center.y + outerRadius * sin(angleRad)).toFloat()

                    val isTickActive = i <= activeTicks && activeTicks > 0
                    val tickColor = if (isTickActive) statusColor else Color(0xFF262626)
                    val tickStroke = if (isTickActive) 2.5.dp.toPx() else 1.5.dp.toPx()

                    drawLine(
                        color = tickColor,
                        start = Offset(startX, startY),
                        end = Offset(endX, endY),
                        strokeWidth = tickStroke,
                        cap = StrokeCap.Round
                    )
                }

                // Inner fine circle
                drawCircle(
                    color = NothingBorder,
                    radius = innerRadius - 6.dp.toPx(),
                    style = Stroke(width = 1.dp.toPx())
                )
            }

            // Central Monospace Score Display
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                val scoreDisplay = (animatedProgress.value * 100).toInt()
                val formattedScore = if (scoreDisplay == 0) "0" else "$scoreDisplay"

                Text(
                    text = formattedScore,
                    fontFamily = FontFamily.Monospace,
                    fontSize = if (formattedScore == "0") 46.sp else 42.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = (-1).sp,
                    color = NothingWhite
                )

                Text(
                    text = "RISK INDEX / 100",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.6.sp,
                    color = NothingGrey
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Nothing OS Status Pill
        Box(
            modifier = Modifier
                .clip(CircleShape)
                .background(pillBg)
                .border(1.dp, pillBorder, CircleShape)
                .padding(horizontal = 16.dp, vertical = 6.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = glyphSymbol,
                    fontSize = 11.sp,
                    color = statusColor
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = statusLabel,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.4.sp,
                    color = statusColor
                )
            }
        }
    }
}

private data class Tuple5<A, B, C, D, E>(
    val a: A, val b: B, val c: C, val d: D, val e: E
)
