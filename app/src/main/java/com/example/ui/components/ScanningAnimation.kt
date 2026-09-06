package com.example.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.NothingBorder
import com.example.ui.theme.NothingGrey
import com.example.ui.theme.NothingLightGrey
import com.example.ui.theme.NothingRed
import com.example.ui.theme.NothingSurface
import com.example.ui.theme.NothingWhite
import kotlinx.coroutines.delay
import kotlin.math.cos
import kotlin.math.sin

/**
 * Nothing OS Glyph Radar & Telemetry Stream.
 * Features dot-matrix concentric radar circles, swept glyph sector, and terminal line steps.
 */
@Composable
fun ScanningRadarDialog(
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "radar")
    val sweepAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(1800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "sweepAngle"
    )

    var currentStepIndex by remember { mutableIntStateOf(0) }
    val stepLogs = listOf(
        Pair("L1_LEXICAL", "Analyzing domain structure & TLD heuristics..."),
        Pair("L2_SQL_DB", "Querying verified bank & gov authorities registry..."),
        Pair("L3_NLP", "Evaluating statistical urgency & threat signals..."),
        Pair("L4_NER_ID", "Cross-checking brand entity mismatch matrices..."),
        Pair("SYNTHESIS", "Aggregating multi-tier evidence score...")
    )

    LaunchedEffect(Unit) {
        while (true) {
            delay(500)
            currentStepIndex = (currentStepIndex + 1) % stepLogs.size
        }
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(NothingSurface)
            .border(1.dp, NothingBorder, RoundedCornerShape(24.dp))
            .padding(22.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Nothing OS Glyph Radar Canvas
            Box(
                modifier = Modifier.size(130.dp),
                contentAlignment = Alignment.Center
            ) {
                Canvas(modifier = Modifier.size(120.dp)) {
                    val center = Offset(size.width / 2, size.height / 2)
                    val radius = size.minDimension / 2
                    val dashedEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 6f), 0f)

                    // Concentric dashed rings (Nothing OS Glyph styling)
                    drawCircle(color = Color(0xFF222222), radius = radius * 0.35f, style = Stroke(1.5f))
                    drawCircle(color = Color(0xFF222222), radius = radius * 0.7f, style = Stroke(1.5f, pathEffect = dashedEffect))
                    drawCircle(color = Color(0xFF333333), radius = radius, style = Stroke(1.5f))

                    // Crosshair grid
                    drawLine(
                        color = Color(0xFF222222),
                        start = Offset(center.x, 0f),
                        end = Offset(center.x, size.height),
                        strokeWidth = 1f
                    )
                    drawLine(
                        color = Color(0xFF222222),
                        start = Offset(0f, center.y),
                        end = Offset(size.width, center.y),
                        strokeWidth = 1f
                    )

                    // Sweeping radar wedge
                    val sweepBrush = Brush.sweepGradient(
                        0.0f to Color.Transparent,
                        0.75f to Color.Transparent,
                        1.0f to NothingRed.copy(alpha = 0.6f),
                        center = center
                    )
                    drawCircle(brush = sweepBrush, radius = radius)

                    // Rotating indicator dot on perimeter
                    val rad = Math.toRadians(sweepAngle.toDouble())
                    val dotX = (center.x + radius * cos(rad)).toFloat()
                    val dotY = (center.y + radius * sin(rad)).toFloat()
                    drawCircle(color = NothingWhite, radius = 3.dp.toPx(), center = Offset(dotX, dotY))
                }

                // Central red glyph dot
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .clip(CircleShape)
                        .background(NothingRed)
                )
            }

            Spacer(modifier = Modifier.height(18.dp))

            // Step Header
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                NothingGlyphPulse(color = NothingRed)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "RUNNING MULTI-LAYER SCAN",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.6.sp,
                    color = NothingWhite
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Step Log
            val current = stepLogs[currentStepIndex]
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color(0xFF1E1E1E))
                    .border(1.dp, Color(0xFF333333), RoundedCornerShape(8.dp))
                    .padding(horizontal = 10.dp, vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "[${current.first}]",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = NothingRed
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = current.second,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = NothingLightGrey,
                    maxLines = 1
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Dot Matrix Progress Tracker
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                stepLogs.indices.forEach { index ->
                    val isActive = index == currentStepIndex
                    val isCompleted = index < currentStepIndex
                    Box(
                        modifier = Modifier
                            .size(if (isActive) 10.dp else 6.dp)
                            .clip(CircleShape)
                            .background(
                                when {
                                    isActive -> NothingRed
                                    isCompleted -> NothingWhite
                                    else -> Color(0xFF333333)
                                }
                            )
                    )
                }
            }
        }
    }
}
