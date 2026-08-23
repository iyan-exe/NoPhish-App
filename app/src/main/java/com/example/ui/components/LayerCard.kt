package com.example.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.AnalysisBreakdown
import com.example.ui.theme.NothingBorder
import com.example.ui.theme.NothingBorderSubtle
import com.example.ui.theme.NothingGrey
import com.example.ui.theme.NothingLightGrey
import com.example.ui.theme.NothingRed
import com.example.ui.theme.NothingSurface
import com.example.ui.theme.NothingSurfaceElevated
import com.example.ui.theme.NothingWhite
import com.example.ui.theme.StatusPhishing
import com.example.ui.theme.StatusSafe
import com.example.ui.theme.StatusSuspicious

@Composable
fun LayerBreakdownSection(
    breakdown: AnalysisBreakdown,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // Layer 1: URL Structure
        val urlHasThreat = breakdown.urlStructure.contains("anomal", ignoreCase = true) ||
                breakdown.urlStructure.contains("threat", ignoreCase = true) ||
                breakdown.urlStructure.contains("typo", ignoreCase = true)
        LayerCard(
            layerIndex = "01",
            title = "URL Structure & Lexical",
            subtitle = "Domain dissection, TLD checks & typosquatting detection",
            statusText = if (urlHasThreat) "Threat Found" else "Verified Clean",
            statusColor = if (urlHasThreat) StatusPhishing else StatusSafe,
            detailContent = breakdown.urlStructure,
            defaultExpanded = true
        )

        // Layer 2: Whitelist & Threat Intel
        val isWhitelisted = breakdown.whitelistStatus.contains("Match Found", ignoreCase = true)
        LayerCard(
            layerIndex = "02",
            title = "SQL Whitelist & Intel",
            subtitle = "RBI/Gov verified registry & threat signature matching",
            statusText = breakdown.whitelistStatus,
            statusColor = if (isWhitelisted) StatusSafe else StatusSuspicious,
            detailContent = "Database status: ${breakdown.whitelistStatus}. Domain cross-referenced with enterprise verified authority repository and active threat telemetry signatures.",
            defaultExpanded = true
        )

        // Layer 3: NLP & Urgency Analysis
        val hasNlpUrgency = breakdown.nlpUrgencyCheck.contains("pressure", ignoreCase = true) ||
                breakdown.nlpUrgencyCheck.contains("deadline", ignoreCase = true) ||
                breakdown.nlpUrgencyCheck.contains("urgent", ignoreCase = true)
        LayerCard(
            layerIndex = "03",
            title = "NLP Urgency & Semantics",
            subtitle = "Evaluation of fear triggers, deadlines & panic tactics",
            statusText = if (hasNlpUrgency) "Urgency Flagged" else "Neutral Sentiment",
            statusColor = if (hasNlpUrgency) StatusPhishing else StatusSafe,
            detailContent = breakdown.nlpUrgencyCheck,
            defaultExpanded = true
        )

        // Layer 4: Brand Impersonation & NER Check
        val hasImpersonation = breakdown.brandImpersonation.contains("untrusted", ignoreCase = true) ||
                breakdown.brandImpersonation.contains("mismatch", ignoreCase = true) ||
                breakdown.brandImpersonation.contains("claims", ignoreCase = true)
        LayerCard(
            layerIndex = "04",
            title = "Brand NER Verification",
            subtitle = "Named Entity Recognition checking domain authority vs claimed brand",
            statusText = if (hasImpersonation) "Brand Mismatch" else "Authentic / N/A",
            statusColor = if (hasImpersonation) StatusPhishing else StatusSafe,
            detailContent = breakdown.brandImpersonation,
            defaultExpanded = true
        )
    }
}

@Composable
fun LayerCard(
    layerIndex: String,
    title: String,
    subtitle: String,
    statusText: String,
    statusColor: Color,
    detailContent: String,
    defaultExpanded: Boolean = false,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(defaultExpanded) }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .background(NothingSurface)
            .border(1.dp, NothingBorder, RoundedCornerShape(20.dp))
            .clickable { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.weight(1f)
                ) {
                    // Nothing OS Tag e.g. [01]
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(Color(0xFF222222))
                            .border(1.dp, Color(0xFF333333), RoundedCornerShape(6.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "[$layerIndex]",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = NothingWhite
                        )
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(
                        text = title,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingWhite
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Status Pill with dot
                    Row(
                        modifier = Modifier
                            .clip(CircleShape)
                            .background(statusColor.copy(alpha = 0.12f))
                            .border(1.dp, statusColor.copy(alpha = 0.3f), CircleShape)
                            .padding(horizontal = 8.dp, vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(5.dp)
                                .clip(CircleShape)
                                .background(statusColor)
                        )
                        Spacer(modifier = Modifier.width(5.dp))
                        Text(
                            text = statusText,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = statusColor
                        )
                    }

                    Spacer(modifier = Modifier.width(4.dp))

                    Icon(
                        imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = if (expanded) "Collapse" else "Expand",
                        tint = NothingGrey,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            Text(
                text = subtitle,
                fontSize = 11.sp,
                color = NothingGrey,
                modifier = Modifier.padding(top = 4.dp)
            )

            AnimatedVisibility(
                visible = expanded,
                enter = fadeIn(
                    animationSpec = tween(180, easing = CubicBezierEasing(0.2f, 0f, 0f, 1f))
                ) + expandVertically(
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    )
                ),
                exit = fadeOut(
                    animationSpec = tween(140, easing = CubicBezierEasing(0.2f, 0f, 0f, 1f))
                ) + shrinkVertically(
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioNoBouncy,
                        stiffness = Spring.StiffnessMedium
                    )
                )
            ) {
                Column(modifier = Modifier.padding(top = 10.dp)) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(NothingSurfaceElevated)
                            .border(1.dp, NothingBorderSubtle, RoundedCornerShape(12.dp))
                            .padding(12.dp)
                    ) {
                        Text(
                            text = detailContent,
                            fontFamily = FontFamily.SansSerif,
                            fontSize = 12.sp,
                            lineHeight = 17.sp,
                            color = NothingLightGrey
                        )
                    }
                }
            }
        }
    }
}
