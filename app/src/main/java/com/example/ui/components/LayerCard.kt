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
import com.example.data.model.EngineTelemetry
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
    telemetry: EngineTelemetry = EngineTelemetry(),
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // Layer 1: Real Supervised Machine Learning Classifier
        val mlProbPercent = (telemetry.mlProbability * 100.0f)
        val isMlPhishing = telemetry.mlProbability >= 0.50f
        val mlStatusText = if (isMlPhishing) "${"%.1f".format(mlProbPercent)}% Phish" else "${"%.1f".format(100.0f - mlProbPercent)}% Legit"
        val mlStatusColor = if (telemetry.mlProbability >= 0.65f) StatusPhishing else if (telemetry.mlProbability >= 0.35f) StatusSuspicious else StatusSafe

        val mlDetailBuilder = StringBuilder()
        val versionTag = if (telemetry.modelVersion.isNotBlank()) " [${telemetry.modelVersion}]" else ""
        mlDetailBuilder.append("Model: Supervised Logistic Classifier$versionTag (24 features, L2 regularized)\n")
        mlDetailBuilder.append("• Phishing Probability: ${"%.2f".format(telemetry.mlProbability * 100)}%\n")
        mlDetailBuilder.append("• Statistical Confidence: ${"%.1f".format(telemetry.mlConfidence)}%\n")
        if (telemetry.mlTopContributors.isNotEmpty()) {
            mlDetailBuilder.append("• Top ML Attribution Weights:\n")
            telemetry.mlTopContributors.forEach { contrib ->
                mlDetailBuilder.append("   - $contrib\n")
            }
        }

        LayerCard(
            layerIndex = "01",
            title = "Supervised ML Classifier",
            subtitle = "24-dimensional normalized URL vector classification",
            statusText = mlStatusText,
            statusColor = mlStatusColor,
            detailContent = mlDetailBuilder.toString().trim(),
            defaultExpanded = true
        )

        // Layer 2: Real RAG Vector Space Model & Cosine Retrieval
        val ragSimPercent = (telemetry.ragCosineSimilarity * 100.0f)
        val hasRagMatch = telemetry.ragTopMatch != null && telemetry.ragCosineSimilarity >= 0.20f
        val ragStatusText = if (hasRagMatch) "${"%.1f".format(ragSimPercent)}% Sim Match" else "No Threat Match"
        val ragStatusColor = if (telemetry.ragCosineSimilarity >= 0.40f) StatusPhishing else if (hasRagMatch) StatusSuspicious else StatusSafe

        val ragDetailBuilder = StringBuilder()
        ragDetailBuilder.append("Engine: TF-IDF Vector Space Model & Cosine Similarity\n")
        if (hasRagMatch) {
            ragDetailBuilder.append("• Top Retrieved Campaign: ${telemetry.ragTopMatch}\n")
            ragDetailBuilder.append("• Cosine Semantic Proximity: ${"%.1f".format(ragSimPercent)}%\n")
            if (telemetry.ragMatchedIocs.isNotEmpty()) {
                ragDetailBuilder.append("• Matched Campaign IOCs: ${telemetry.ragMatchedIocs.joinToString(", ")}\n")
            }
        } else {
            ragDetailBuilder.append("• Cosine Proximity: ${"%.1f".format(ragSimPercent)}% (Below threat activation threshold 20%)\n")
            ragDetailBuilder.append("• No matching campaign signatures retrieved from verified knowledge corpus.\n")
        }

        LayerCard(
            layerIndex = "02",
            title = "RAG Vector Threat Intelligence",
            subtitle = "TF-IDF Vector Space semantic similarity against threat corpus",
            statusText = ragStatusText,
            statusColor = ragStatusColor,
            detailContent = ragDetailBuilder.toString().trim(),
            defaultExpanded = true
        )

        // Layer 3: Real NLP Semantic & Psychological Coercion
        val nlpUrgency = telemetry.nlpUrgencyScore
        val hasNlpUrgency = nlpUrgency >= 25 || telemetry.nlpTactics.isNotEmpty()
        val nlpStatusText = if (hasNlpUrgency) "$nlpUrgency/100 Urgency" else "Neutral Sentiment"
        val nlpStatusColor = if (nlpUrgency >= 60) StatusPhishing else if (hasNlpUrgency) StatusSuspicious else StatusSafe

        val nlpDetailBuilder = StringBuilder()
        nlpDetailBuilder.append(breakdown.nlpUrgencyCheck).append("\n")
        if (telemetry.nlpImperativeRatio > 0.0f) {
            nlpDetailBuilder.append("• Imperative Command Ratio: ${"%.0f".format(telemetry.nlpImperativeRatio * 100)}% of clauses\n")
        }
        if (telemetry.nlpTactics.isNotEmpty()) {
            nlpDetailBuilder.append("• Psychological Vectors: ${telemetry.nlpTactics.joinToString("; ")}\n")
        }

        LayerCard(
            layerIndex = "03",
            title = "Statistical NLP & Urgency Engine",
            subtitle = "Statistical + rule-based imperative mood, temporal pressure & loss aversion analysis",
            statusText = nlpStatusText,
            statusColor = nlpStatusColor,
            detailContent = nlpDetailBuilder.toString().trim(),
            defaultExpanded = true
        )

        // Layer 4: Brand Impersonation & Authority Check
        val hasImpersonation = breakdown.brandImpersonation.contains("untrusted", ignoreCase = true) ||
                breakdown.brandImpersonation.contains("mismatch", ignoreCase = true) ||
                breakdown.brandImpersonation.contains("claims", ignoreCase = true)
        LayerCard(
            layerIndex = "04",
            title = "Brand Spoofing & Authority Check",
            subtitle = "Cross-checks brand entities against authoritative domain registries",
            statusText = if (hasImpersonation) "Brand Mismatch" else "Authentic / N/A",
            statusColor = if (hasImpersonation) StatusPhishing else StatusSafe,
            detailContent = breakdown.brandImpersonation,
            defaultExpanded = true
        )

        // Layer 5: URL Structure & Obfuscation Heuristics
        val urlHasThreat = breakdown.urlStructure.contains("anomal", ignoreCase = true) ||
                breakdown.urlStructure.contains("threat", ignoreCase = true) ||
                breakdown.urlStructure.contains("typo", ignoreCase = true) ||
                breakdown.urlStructure.contains("leetspeak", ignoreCase = true) ||
                breakdown.urlStructure.contains("l0gin", ignoreCase = true)
        val urlDetail = buildString {
            append(breakdown.urlStructure)
            if (telemetry.shannonEntropy > 0.0f) {
                append("\n• Host Shannon Entropy: ${"%.2f".format(telemetry.shannonEntropy)} bits")
            }
            if (telemetry.urlLength > 0) {
                append(" | Total URL Length: ${telemetry.urlLength} characters")
            }
        }

        LayerCard(
            layerIndex = "05",
            title = "URL Structure & Lexical Obfuscation",
            subtitle = "Path leetspeak analysis, open redirects & entropy evaluation",
            statusText = if (urlHasThreat) "Anomaly Detected" else "Verified Clean",
            statusColor = if (urlHasThreat) StatusPhishing else StatusSafe,
            detailContent = urlDetail,
            defaultExpanded = true
        )

        // Layer 6: Whitelist & Threat Intel
        val isWhitelisted = breakdown.whitelistStatus.contains("Match Found", ignoreCase = true)
        LayerCard(
            layerIndex = "06",
            title = "SQLite Room Whitelist & Registry",
            subtitle = "RBI .bank.in registry & enterprise verified authority cross-check",
            statusText = breakdown.whitelistStatus,
            statusColor = if (isWhitelisted) StatusSafe else StatusSuspicious,
            detailContent = "Database status: ${breakdown.whitelistStatus}. Query executed live on local SQLite Room repository.",
            defaultExpanded = false
        )

        // Layer 7: HTML Webpage & Credential Siphoning
        val htmlHasThreat = breakdown.htmlAnalysis.contains("credential", ignoreCase = true) ||
                breakdown.htmlAnalysis.contains("siphon", ignoreCase = true) ||
                breakdown.htmlAnalysis.contains("external", ignoreCase = true) ||
                breakdown.htmlAnalysis.contains("scareware", ignoreCase = true)
        LayerCard(
            layerIndex = "07",
            title = "HTML & Credential Harvesting Page Inspector",
            subtitle = "Form action destination, password inputs, obfuscated JS & meta-refresh",
            statusText = if (htmlHasThreat) "Threat In HTML" else if (breakdown.htmlAnalysis.isNotBlank()) "Clean / Evaluated" else "No HTML Provided",
            statusColor = if (htmlHasThreat) StatusPhishing else StatusSafe,
            detailContent = if (breakdown.htmlAnalysis.isNotBlank()) breakdown.htmlAnalysis else "No HTML source provided for this scan target. Analyzed based on URL and query signatures.",
            defaultExpanded = htmlHasThreat
        )

        // Layer 8: Redirect Chain & Cloaking
        val redirectHasThreat = breakdown.redirectChain.contains("open redirect", ignoreCase = true) ||
                breakdown.redirectChain.contains("excessive", ignoreCase = true) ||
                breakdown.redirectChain.contains("shortener", ignoreCase = true)
        LayerCard(
            layerIndex = "08",
            title = "Redirect Chain & Cloaking Analyzer",
            subtitle = "Multi-hop redirect inspector, open redirect sinks & shortener unmasking",
            statusText = if (redirectHasThreat) "Redirect Anomaly" else "Direct Route",
            statusColor = if (redirectHasThreat) StatusSuspicious else StatusSafe,
            detailContent = breakdown.redirectChain,
            defaultExpanded = redirectHasThreat
        )

        // Layer 9: Screenshot & Visual Brand Inspection
        val visualHasThreat = breakdown.visualAnalysis.contains("scareware", ignoreCase = true) ||
                breakdown.visualAnalysis.contains("mismatch", ignoreCase = true) ||
                breakdown.visualAnalysis.contains("impersonat", ignoreCase = true)
        LayerCard(
            layerIndex = "09",
            title = "Visual & Screenshot Evidence Inspector",
            subtitle = "Visual branding cues, fake system dialogs & OCR text alignment",
            statusText = if (visualHasThreat) "Visual Threat" else "Clean / N/A",
            statusColor = if (visualHasThreat) StatusPhishing else StatusSafe,
            detailContent = breakdown.visualAnalysis,
            defaultExpanded = visualHasThreat
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
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            lineHeight = 16.sp,
                            color = NothingLightGrey
                        )
                    }
                }
            }
        }
    }
}
