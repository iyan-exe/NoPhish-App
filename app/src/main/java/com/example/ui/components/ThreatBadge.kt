package com.example.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.NothingBorder
import com.example.ui.theme.NothingGreen
import com.example.ui.theme.NothingGreenBorder
import com.example.ui.theme.NothingGreenContainer
import com.example.ui.theme.NothingRed
import com.example.ui.theme.NothingRedBorder
import com.example.ui.theme.NothingRedContainer
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

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ThreatBadgesList(
    threats: List<String>,
    modifier: Modifier = Modifier
) {
    if (threats.isEmpty()) {
        Box(
            modifier = modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(StatusSafeContainer)
                .border(1.dp, StatusSafeBorder, RoundedCornerShape(16.dp))
                .padding(horizontal = 14.dp, vertical = 10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(StatusSafe)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "ZERO ANOMALIES DETECTED — SYSTEM VERIFIED SAFE",
                    fontFamily = FontFamily.Monospace,
                    color = StatusSafe,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                    letterSpacing = 0.5.sp
                )
            }
        }
    } else {
        FlowRow(
            modifier = modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            threats.forEach { threat ->
                ThreatChip(threatText = threat)
            }
        }
    }
}

@Composable
fun ThreatChip(
    threatText: String,
    modifier: Modifier = Modifier
) {
    val isCritical = threatText.contains("Phishing", ignoreCase = true) ||
            threatText.contains("Brand Impersonation", ignoreCase = true) ||
            threatText.contains("Campaign", ignoreCase = true) ||
            threatText.contains("Typosquat", ignoreCase = true)

    val chipBg = if (isCritical) StatusPhishingContainer else StatusSuspiciousContainer
    val chipBorder = if (isCritical) StatusPhishingBorder else StatusSuspiciousBorder
    val accentColor = if (isCritical) StatusPhishing else StatusSuspicious
    val glyphSymbol = if (isCritical) "▲" else "◆"

    Row(
        modifier = modifier
            .clip(CircleShape)
            .background(chipBg)
            .border(1.dp, chipBorder, CircleShape)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = glyphSymbol,
            fontSize = 10.sp,
            color = accentColor
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = threatText,
            color = accentColor,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
