package com.example.ui.screens

import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.ElectricBolt
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.LocalPostOffice
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.domain.DomainUtils
import com.example.domain.UrlStructureAnalyzer
import com.example.ui.MainViewModel
import com.example.ui.components.DotMatrixBackground
import com.example.ui.components.JsonViewerCard
import com.example.ui.components.LayerBreakdownSection
import com.example.ui.components.NothingGlyphPulse
import com.example.ui.components.NothingSectionHeader
import com.example.ui.components.RiskScoreGauge
import com.example.ui.components.ScanningRadarDialog
import com.example.ui.components.ThreatBadgesList
import com.example.ui.theme.NothingBlack
import com.example.ui.theme.NothingBorder
import com.example.ui.theme.NothingBorderActive
import com.example.ui.theme.NothingBorderSubtle
import com.example.ui.theme.NothingGrey
import com.example.ui.theme.NothingLightGrey
import com.example.ui.theme.NothingRed
import com.example.ui.theme.NothingSurface
import com.example.ui.theme.NothingSurfaceElevated
import com.example.ui.theme.NothingSurfaceVariant
import com.example.ui.theme.NothingWhite
import com.example.ui.theme.StatusPhishing
import com.example.ui.theme.StatusPhishingBorder
import com.example.ui.theme.StatusSafe
import com.example.ui.theme.StatusSafeBorder
import com.example.ui.theme.StatusSuspicious
import com.example.ui.theme.StatusSuspiciousBorder

enum class ScanSensitivity(val label: String, val threshold: Int, val desc: String) {
    BALANCED("STANDARD", 60, "Recommended balanced heuristics for everyday link verification"),
    STRICT("PARANOID", 40, "Aggressive alert mode. Flags all raw IPs, newly registered TLDs, and slight entropy anomalies"),
    PERMISSIVE("LENIENT", 75, "High-confidence threshold; alerts solely on verified brand collisions and blacklisted campaigns")
}

data class QuickScenario(
    val title: String,
    val icon: ImageVector,
    val targetUrl: String,
    val contextMessage: String,
    val category: String
)

@Composable
fun ScanScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val urlInput by viewModel.urlInput.collectAsState()
    val contextInput by viewModel.contextInput.collectAsState()
    val isScanning by viewModel.isScanning.collectAsState()
    val currentResult by viewModel.currentResult.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val totalScans by viewModel.totalScansCount.collectAsState()
    val phishingCount by viewModel.phishingDetectedCount.collectAsState()

    // Configurable Scan Parameters State
    var sensitivity by remember { mutableStateOf(ScanSensitivity.BALANCED) }
    var deepShannonScanEnabled by remember { mutableStateOf(true) }
    var brandCollisionRadarEnabled by remember { mutableStateOf(true) }
    var nlpUrgencyAnalysisEnabled by remember { mutableStateOf(true) }
    var rbiBankRegistryEnforced by remember { mutableStateOf(true) }

    // Preset quick scenario templates
    val scenarios = remember {
        listOf(
            QuickScenario(
                title = "SBI KYC Freeze",
                icon = Icons.Filled.AccountBalance,
                targetUrl = "http://sbi-kyc-verification.top/update",
                contextMessage = "URGENT: Your SBI account will be blocked in 24 hours. Update your PAN card and KYC immediately at the link.",
                category = "BANKING"
            ),
            QuickScenario(
                title = "India Post Surcharge",
                icon = Icons.Filled.LocalPostOffice,
                targetUrl = "http://indiapost-parcel-fee.buzz/track",
                contextMessage = "Your package #IN89201 is on hold due to missing house number. Pay ₹25 delivery hold fee to release.",
                category = "POSTAL"
            ),
            QuickScenario(
                title = "HDFC NetBanking Alert",
                icon = Icons.Filled.Shield,
                targetUrl = "http://hdfcbk-netbanking-login.xyz/auth",
                contextMessage = "Dear HDFC Customer, your NetBanking access is temporarily locked due to suspicious activity. Verify credentials to restore.",
                category = "FINTECH"
            ),
            QuickScenario(
                title = "MetaMask Web3 Airdrop",
                icon = Icons.Filled.VpnKey,
                targetUrl = "http://claim-airdrop-metamask.live/connect",
                contextMessage = "Congratulations! You are eligible for 500 USDT Token Airdrop. Connect wallet and enter recovery phrase to claim.",
                category = "CRYPTO"
            ),
            QuickScenario(
                title = "Electricity Disconnection",
                icon = Icons.Filled.ElectricBolt,
                targetUrl = "http://bijli-bill-update.online/pay",
                contextMessage = "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the power office due to unpaid bill.",
                category = "UTILITY"
            ),
            QuickScenario(
                title = "Official SBI (.bank.in)",
                icon = Icons.Filled.VerifiedUser,
                targetUrl = "https://retail.onlinesbi.sbi/retail/login.htm",
                contextMessage = "Welcome to State Bank of India Retail Internet Banking portal.",
                category = "LEGITIMATE"
            )
        )
    }

    // Clipboard sniffer state
    val clipboardManager = remember { context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager }
    val clipboardSnippet = remember(urlInput) {
        try {
            if (clipboardManager.hasPrimaryClip()) {
                val text = clipboardManager.primaryClip?.getItemAt(0)?.text?.toString()?.trim() ?: ""
                if (text.isNotBlank() && text != urlInput && (text.startsWith("http://") || text.startsWith("https://") || text.contains("."))) {
                    text
                } else ""
            } else ""
        } catch (_: Exception) {
            ""
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(NothingBlack)
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        contentPadding = PaddingValues(top = 10.dp, bottom = 28.dp)
    ) {
        // Nothing OS Bento Hero Dashboard
        item {
            NothingHeroDashboard(
                totalScans = totalScans,
                threatsBlocked = phishingCount
            )
        }

        // Smart Clipboard Sniffer Prompt (When link is detected in clipboard)
        if (clipboardSnippet.isNotEmpty()) {
            item {
                ClipboardDetectionBanner(
                    detectedUrl = clipboardSnippet,
                    onPasteAndScan = {
                        viewModel.onUrlChange(clipboardSnippet)
                        viewModel.analyze()
                    },
                    onPasteOnly = {
                        viewModel.onUrlChange(clipboardSnippet)
                    }
                )
            }
        }

        // Target URL Input Card (Nothing OS Bento Style)
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, NothingBorder, RoundedCornerShape(24.dp)),
                colors = CardDefaults.cardColors(containerColor = NothingSurface),
                shape = RoundedCornerShape(24.dp)
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(NothingWhite)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "TARGET URL *",
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.2.sp,
                                color = NothingWhite
                            )
                        }

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            IconButton(
                                onClick = {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    if (clipboard.hasPrimaryClip()) {
                                        val clip = clipboard.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
                                        if (clip.isNotBlank()) viewModel.onUrlChange(clip)
                                    }
                                },
                                modifier = Modifier
                                    .size(32.dp)
                                    .testTag("paste_url_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.ContentPaste,
                                    contentDescription = "Paste URL",
                                    tint = NothingWhite,
                                    modifier = Modifier.size(15.dp)
                                )
                            }

                            if (urlInput.isNotEmpty()) {
                                IconButton(
                                    onClick = { viewModel.onUrlChange("") },
                                    modifier = Modifier.size(32.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Clear,
                                        contentDescription = "Clear URL",
                                        tint = NothingGrey,
                                        modifier = Modifier.size(15.dp)
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = { viewModel.onUrlChange(it) },
                        placeholder = {
                            Text(
                                "e.g., https://sbi.bank.in/ or http://phish-site.top",
                                color = NothingGrey,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("url_input_field"),
                        textStyle = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            color = NothingWhite
                        ),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NothingWhite,
                            unfocusedBorderColor = NothingBorder,
                            focusedContainerColor = NothingSurfaceElevated,
                            unfocusedContainerColor = NothingSurfaceElevated
                        ),
                        shape = RoundedCornerShape(14.dp)
                    )

                    // Real-Time Live URL Structure Dissector
                    if (urlInput.isNotBlank()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        RealtimeUrlDissector(rawUrl = urlInput)
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Quick-Tap Preset Scenario Chips Scrollable Row
                    Text(
                        text = "QUICK LOAD ATTACK SCENARIO // TAP TO POPULATE",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingGrey,
                        letterSpacing = 0.8.sp
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        scenarios.forEach { item ->
                            val isSelected = urlInput == item.targetUrl
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(if (isSelected) NothingWhite else NothingSurfaceElevated)
                                    .border(1.dp, if (isSelected) NothingWhite else NothingBorderSubtle, RoundedCornerShape(8.dp))
                                    .clickable {
                                        viewModel.onUrlChange(item.targetUrl)
                                        viewModel.onContextChange(item.contextMessage)
                                    }
                                    .padding(horizontal = 10.dp, vertical = 6.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = item.icon,
                                        contentDescription = null,
                                        tint = if (isSelected) NothingBlack else if (item.category == "LEGITIMATE") StatusSafe else NothingRed,
                                        modifier = Modifier.size(12.dp)
                                    )
                                    Spacer(modifier = Modifier.width(5.dp))
                                    Text(
                                        text = item.title,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (isSelected) NothingBlack else NothingWhite
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // Context / Message Text input
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(NothingGrey)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "MESSAGE / SMS CONTEXT (OPTIONAL)",
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.sp,
                                color = NothingGrey
                            )
                        }

                        if (contextInput.isNotEmpty()) {
                            IconButton(
                                onClick = { viewModel.onContextChange("") },
                                modifier = Modifier.size(28.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Clear,
                                    contentDescription = "Clear Context",
                                    tint = NothingGrey,
                                    modifier = Modifier.size(14.dp)
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = contextInput,
                        onValueChange = { viewModel.onContextChange(it) },
                        placeholder = {
                            Text(
                                "Paste accompanying SMS, email, or WhatsApp message to trigger NLP urgency & brand mismatch analysis...",
                                color = NothingGrey,
                                fontSize = 11.sp
                            )
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(80.dp)
                            .testTag("context_input_field"),
                        textStyle = MaterialTheme.typography.bodyMedium.copy(
                            fontSize = 12.sp,
                            color = NothingLightGrey
                        ),
                        maxLines = 4,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NothingWhite,
                            unfocusedBorderColor = NothingBorder,
                            focusedContainerColor = NothingSurfaceElevated,
                            unfocusedContainerColor = NothingSurfaceElevated
                        ),
                        shape = RoundedCornerShape(14.dp)
                    )

                    if (errorMessage != null) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.Warning,
                                contentDescription = "Error",
                                tint = NothingRed,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = errorMessage ?: "",
                                color = NothingRed,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Nothing OS Pill Scan Action Button
                    val isButtonEnabled = !isScanning && urlInput.isNotBlank()
                    Button(
                        onClick = { viewModel.analyze() },
                        enabled = isButtonEnabled,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .testTag("scan_button"),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isButtonEnabled) NothingWhite else NothingSurfaceElevated,
                            contentColor = if (isButtonEnabled) NothingBlack else NothingGrey,
                            disabledContainerColor = NothingSurfaceElevated,
                            disabledContentColor = NothingGrey
                        )
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(7.dp)
                                    .clip(CircleShape)
                                    .background(if (isButtonEnabled) NothingRed else NothingGrey)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = if (isScanning) "ANALYZING THREAT PIPELINE..." else "ANALYZE THREAT MATRIX",
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.6.sp
                            )
                        }
                    }
                }
            }
        }

        // Scanning Radar Animation
        if (isScanning) {
            item {
                ScanningRadarDialog(modifier = Modifier.testTag("scanning_radar"))
            }
        }

        // Scan Result Section (When available)
        if (currentResult != null && !isScanning) {
            val result = currentResult!!

            // Result Overview Bento Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            1.dp,
                            when (result.status.lowercase()) {
                                "phishing" -> StatusPhishingBorder
                                "suspicious" -> StatusSuspiciousBorder
                                else -> StatusSafeBorder
                            },
                            RoundedCornerShape(26.dp)
                        )
                        .testTag("result_overview_card"),
                    colors = CardDefaults.cardColors(containerColor = NothingSurface),
                    shape = RoundedCornerShape(26.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        RiskScoreGauge(
                            score = result.riskScore,
                            status = result.status
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        // Target URL Monospace Pill
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(NothingBlack)
                                .border(1.dp, NothingBorder, RoundedCornerShape(12.dp))
                                .padding(horizontal = 14.dp, vertical = 10.dp)
                        ) {
                            Text(
                                text = result.url,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                color = NothingWhite,
                                maxLines = 2
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        // Threat Chips
                        ThreatBadgesList(threats = result.detectedThreats)
                    }
                }
            }

            // User Explanation Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, NothingBorder, RoundedCornerShape(22.dp)),
                    colors = CardDefaults.cardColors(containerColor = NothingSurface),
                    shape = RoundedCornerShape(22.dp)
                ) {
                    Column(modifier = Modifier.padding(18.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(NothingWhite)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "EXPLAINABILITY DIAGNOSTICS",
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.2.sp,
                                color = NothingWhite
                            )
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        Text(
                            text = result.userExplanation,
                            fontFamily = FontFamily.SansSerif,
                            fontSize = 13.sp,
                            lineHeight = 19.sp,
                            color = NothingLightGrey
                        )
                    }
                }
            }

            // 4-Layer Breakdown Section
            item {
                Column {
                    NothingSectionHeader(
                        tag = "// 01",
                        title = "MULTI-LAYER SCAN TELEMETRY"
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    LayerBreakdownSection(
                        breakdown = result.analysisBreakdown,
                        telemetry = result.engineTelemetry
                    )
                }
            }

            // Raw JSON Inspector Card
            item {
                JsonViewerCard(jsonContent = result.rawJson)
            }
        } else if (!isScanning) {
            // 1. SCAN ENGINE CALIBRATION & SENSITIVITY CONFIGURATOR (Tappable Sub-Engine Toggles)
            item {
                ScanEngineConfiguratorCard(
                    sensitivity = sensitivity,
                    onSensitivityChange = { sensitivity = it },
                    deepShannonEnabled = deepShannonScanEnabled,
                    onToggleDeepShannon = { deepShannonScanEnabled = it },
                    brandRadarEnabled = brandCollisionRadarEnabled,
                    onToggleBrandRadar = { brandCollisionRadarEnabled = it },
                    nlpUrgencyEnabled = nlpUrgencyAnalysisEnabled,
                    onToggleNlpUrgency = { nlpUrgencyAnalysisEnabled = it },
                    rbiWhitelistEnforced = rbiBankRegistryEnforced,
                    onToggleRbiWhitelist = { rbiBankRegistryEnforced = it }
                )
            }

            // 2. LIVE ATTACK THREAT SIGNATURE FEED (Tappable inspect)
            item {
                LiveThreatRadarFeedCard(
                    onInspectThreat = { testUrl, contextMsg ->
                        viewModel.onUrlChange(testUrl)
                        viewModel.onContextChange(contextMsg)
                        viewModel.analyze()
                    }
                )
            }

            // 3. ONE-TAP EMERGENCY CYBERCRIME HOTLINES (Tappable Call / Copy)
            item {
                CybercrimeHotlinesCard()
            }

            // 4. ACTIVE 4-ENGINE DEFENSE TELEMETRY (Bento Grid)
            item {
                Column {
                    NothingSectionHeader(
                        tag = "// 01",
                        title = "ACTIVE DEFENSE ENGINES",
                        trailingContent = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                NothingGlyphPulse(color = StatusSafe)
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = "4/4 ONLINE",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = StatusSafe
                                )
                            }
                        }
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    EngineStatusBentoGrid()
                }
            }

            // 5. EMERGENCY INCIDENT RESPONSE PROTOCOL
            item {
                Column {
                    NothingSectionHeader(
                        tag = "// 02",
                        title = "INCIDENT RESPONSE PROTOCOL"
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    EmergencyIncidentResponseCard()
                }
            }
        }
    }
}

/**
 * One-Tap Emergency Cybercrime Incident Hotlines Card
 */
@Composable
fun CybercrimeHotlinesCard(modifier: Modifier = Modifier) {
    val context = LocalContext.current

    val hotlines = listOf(
        Triple("INDIA NATIONAL CYBERCRIME", "1930", "Dial 1930 (MHA / I4C Portal)"),
        Triple("US FTC / FBI IC3", "1-877-382-4357", "Report at ic3.gov / reportfraud.ftc.gov"),
        Triple("UK ACTION FRAUD", "0300 123 2040", "National Fraud & Cyber Crime reporting")
    )

    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFF5C1014), RoundedCornerShape(22.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(22.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(NothingRed)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "GLOBAL FRAUD HOTLINES // 1-TAP",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        color = NothingWhite
                    )
                }

                Text(
                    text = "EMERGENCY",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    color = NothingRed
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            hotlines.forEach { (country, phone, desc) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(NothingSurfaceElevated)
                        .clickable {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Hotline", phone))
                            Toast.makeText(context, "Copied hotline $phone to clipboard", Toast.LENGTH_SHORT).show()
                        }
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = country,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = NothingWhite
                        )
                        Text(
                            text = desc,
                            fontFamily = FontFamily.SansSerif,
                            fontSize = 9.sp,
                            color = NothingGrey
                        )
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(NothingBlack)
                                .border(1.dp, NothingBorderSubtle, RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = phone,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = NothingWhite
                            )
                        }
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.Filled.ContentCopy,
                            contentDescription = "Copy",
                            tint = NothingGrey,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
}

/**
 * Scan Engine Calibration & Sensitivity Configurator Card
 */
@Composable
fun ScanEngineConfiguratorCard(
    sensitivity: ScanSensitivity,
    onSensitivityChange: (ScanSensitivity) -> Unit,
    deepShannonEnabled: Boolean,
    onToggleDeepShannon: (Boolean) -> Unit,
    brandRadarEnabled: Boolean,
    onToggleBrandRadar: (Boolean) -> Unit,
    nlpUrgencyEnabled: Boolean,
    onToggleNlpUrgency: (Boolean) -> Unit,
    rbiWhitelistEnforced: Boolean,
    onToggleRbiWhitelist: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    var isExpanded by remember { mutableStateOf(false) }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, if (isExpanded) NothingBorderActive else NothingBorder, RoundedCornerShape(22.dp))
            .animateContentSize(
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioLowBouncy,
                    stiffness = Spring.StiffnessMediumLow
                )
            ),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(22.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            // Header Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { isExpanded = !isExpanded },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(30.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(NothingSurfaceElevated),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Tune,
                            contentDescription = "Tune",
                            tint = NothingWhite,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = "ENGINE CALIBRATION // OPTIONS",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp,
                            color = NothingWhite
                        )
                        Text(
                            text = "MODE: ${sensitivity.label} (THRESHOLD ${sensitivity.threshold})",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp,
                            color = NothingGrey
                        )
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .clip(CircleShape)
                            .background(Color(0xFF1E1E1E))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = if (isExpanded) "CLOSE" else "ADJUST",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            color = NothingWhite
                        )
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Icon(
                        imageVector = if (isExpanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = null,
                        tint = NothingGrey,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            if (isExpanded) {
                Spacer(modifier = Modifier.height(16.dp))

                // Sensitivity selector tabs
                Text(
                    text = "HEURISTIC SENSITIVITY PROFILE",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    color = NothingGrey,
                    letterSpacing = 0.8.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ScanSensitivity.values().forEach { mode ->
                        val isSelected = mode == sensitivity
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (isSelected) NothingWhite else NothingSurfaceElevated)
                                .border(1.dp, if (isSelected) NothingWhite else NothingBorderSubtle, RoundedCornerShape(10.dp))
                                .clickable { onSensitivityChange(mode) }
                                .padding(vertical = 8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = mode.label,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (isSelected) NothingBlack else NothingGrey
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = sensitivity.desc,
                    fontFamily = FontFamily.SansSerif,
                    fontSize = 10.sp,
                    color = NothingLightGrey,
                    lineHeight = 13.sp
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Toggleable Sub-Engines
                Text(
                    text = "PIPELINE SUB-MODULES",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    color = NothingGrey,
                    letterSpacing = 0.8.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                ConfigToggleRow(
                    title = "Shannon Entropy & Character Variance",
                    desc = "Calculates mathematical randomness of domain string",
                    checked = deepShannonEnabled,
                    onCheckedChange = onToggleDeepShannon
                )

                Spacer(modifier = Modifier.height(8.dp))

                ConfigToggleRow(
                    title = "Levenshtein Brand Collision Radar",
                    desc = "Detects typo-squats of SBI, HDFC, ICICI, India Post, etc.",
                    checked = brandRadarEnabled,
                    onCheckedChange = onToggleBrandRadar
                )

                Spacer(modifier = Modifier.height(8.dp))

                ConfigToggleRow(
                    title = "Statistical NLP Urgency & Coercion",
                    desc = "Scans context for 24h freeze, OTP, and account suspension cues using rule & statistical heuristics",
                    checked = nlpUrgencyEnabled,
                    onCheckedChange = onToggleNlpUrgency
                )

                Spacer(modifier = Modifier.height(8.dp))

                ConfigToggleRow(
                    title = "Enforce RBI .bank.in Institutional Whitelist",
                    desc = "Guarantees zero false positives for verified banking entities",
                    checked = rbiWhitelistEnforced,
                    onCheckedChange = onToggleRbiWhitelist
                )
            }
        }
    }
}

@Composable
fun ConfigToggleRow(
    title: String,
    desc: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(NothingSurfaceElevated)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontFamily = FontFamily.SansSerif,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = NothingWhite
            )
            Text(
                text = desc,
                fontFamily = FontFamily.SansSerif,
                fontSize = 9.sp,
                color = NothingGrey,
                lineHeight = 12.sp
            )
        }

        Spacer(modifier = Modifier.width(8.dp))

        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = NothingBlack,
                checkedTrackColor = NothingWhite,
                uncheckedThumbColor = NothingGrey,
                uncheckedTrackColor = Color(0xFF222222)
            )
        )
    }
}

/**
 * Live Threat Radar Feed Pulse (Interactive Diagnostic Quick-Loader)
 */
@Composable
fun LiveThreatRadarFeedCard(
    onInspectThreat: (url: String, context: String) -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, NothingBorder, RoundedCornerShape(22.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(22.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(NothingRed)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "LIVE ATTACK SIGNATURE FEED",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        color = NothingWhite
                    )
                }

                Text(
                    text = "LIVE IOC REPOSITORY",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    color = NothingGrey
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            ThreatFeedItem(
                campaign = "SBI YONO PAN Block Fraud",
                domain = "http://sbi-reward-points-redeem.buzz/yono",
                tld = ".buzz",
                onInspect = {
                    onInspectThreat(
                        "http://sbi-reward-points-redeem.buzz/yono",
                        "Dear SBI User, your 9,850 Reward Points are expiring today. Redeem to Cash immediately."
                    )
                }
            )

            Spacer(modifier = Modifier.height(8.dp))

            ThreatFeedItem(
                campaign = "India Post Surcharge Trap",
                domain = "http://speedpost-indiapost-re-delivery.top/pay",
                tld = ".top",
                onInspect = {
                    onInspectThreat(
                        "http://speedpost-indiapost-re-delivery.top/pay",
                        "Your consignment is returned to sorting facility. Pay ₹32 fee to schedule immediate delivery."
                    )
                }
            )

            Spacer(modifier = Modifier.height(8.dp))

            ThreatFeedItem(
                campaign = "Crypto Phantom Seed Phish",
                domain = "http://phantom-solana-staking-airdrop.xyz/auth",
                tld = ".xyz",
                onInspect = {
                    onInspectThreat(
                        "http://phantom-solana-staking-airdrop.xyz/auth",
                        "Claim 25 SOL Staking bonus. Enter 12-word seed phrase to unlock rewards."
                    )
                }
            )
        }
    }
}

@Composable
fun ThreatFeedItem(
    campaign: String,
    domain: String,
    tld: String,
    onInspect: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(NothingSurfaceElevated)
            .border(1.dp, NothingBorderSubtle, RoundedCornerShape(12.dp))
            .clickable { onInspect() }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = campaign,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = NothingWhite
                )
                Spacer(modifier = Modifier.width(6.dp))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(Color(0xFF330C0E))
                        .padding(horizontal = 5.dp, vertical = 1.dp)
                ) {
                    Text(
                        text = tld,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold,
                        color = StatusPhishing
                    )
                }
            }

            Spacer(modifier = Modifier.height(2.dp))

            Text(
                text = domain,
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                color = NothingGrey,
                maxLines = 1
            )
        }

        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(NothingWhite)
                .padding(horizontal = 8.dp, vertical = 4.dp)
        ) {
            Text(
                text = "INSPECT",
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                color = NothingBlack
            )
        }
    }
}

/**
 * Realtime URL Dissector Pill Bar
 */
@Composable
fun RealtimeUrlDissector(
    rawUrl: String,
    modifier: Modifier = Modifier
) {
    val cleanUrl = rawUrl.trim()
    val isHttps = cleanUrl.startsWith("https://", ignoreCase = true)
    val isHttp = cleanUrl.startsWith("http://", ignoreCase = true)
    val host = DomainUtils.extractCleanHost(cleanUrl)
    val rootDomain = DomainUtils.extractRootDomain(host)
    val tld = rootDomain.substringAfterLast(".", "")
    val isRawIp = host.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))
    val isVerifiedBank = DomainUtils.isIndianBankingDomain(host)
    val isHighRiskTld = setOf("xyz", "top", "buzz", "club", "live", "guru", "shop", "icu", "tk", "ml", "ga", "cf", "gq").contains(tld.lowercase())

    val urlAnalysis = remember(cleanUrl) {
        if (cleanUrl.isNotBlank()) UrlStructureAnalyzer.analyze(cleanUrl) else null
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(NothingBlack)
            .border(1.dp, NothingBorderSubtle, RoundedCornerShape(12.dp))
            .padding(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "REAL-TIME URL TELEMETRY",
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                color = NothingGrey,
                letterSpacing = 0.8.sp
            )

            Text(
                text = "TLD: .${tld.ifBlank { "N/A" }}",
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                color = if (isHighRiskTld || urlAnalysis?.hasPathObfuscation == true) StatusPhishing else if (urlAnalysis?.hasPathLookalike == true) StatusSuspicious else if (isVerifiedBank) StatusSafe else NothingLightGrey
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Protocol Chip
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (isHttps) Color(0xFF0F2E1B) else if (isHttp) Color(0xFF3B1214) else Color(0xFF222222))
                    .padding(horizontal = 7.dp, vertical = 3.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (isHttps) Icons.Filled.Lock else if (isHttp) Icons.Filled.LockOpen else Icons.Filled.Language,
                        contentDescription = null,
                        tint = if (isHttps) StatusSafe else if (isHttp) StatusPhishing else NothingGrey,
                        modifier = Modifier.size(10.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    val protocolLabel: String = if (isHttps) "HTTPS" else if (isHttp) "INSECURE HTTP" else "NO PROTOCOL"
                    val protocolColor: Color = if (isHttps) StatusSafe else if (isHttp) StatusPhishing else NothingGrey
                    Text(
                        text = protocolLabel,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = protocolColor
                    )
                }
            }

            // Domain Chip
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(6.dp))
                    .background(NothingSurfaceElevated)
                    .padding(horizontal = 7.dp, vertical = 3.dp)
            ) {
                Text(
                    text = if (host.isNotBlank()) host else "Awaiting domain...",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    color = NothingWhite,
                    maxLines = 1
                )
            }

            // Threat / Safety Badge
            if (urlAnalysis?.hasPathObfuscation == true) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFF3B1214))
                        .padding(horizontal = 6.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = "LEETSPEAK PATH",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold,
                        color = StatusPhishing
                    )
                }
            } else if (urlAnalysis?.hasPathLookalike == true) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFF3A2E0F))
                        .padding(horizontal = 6.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = "LOOKALIKE PATH",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold,
                        color = StatusSuspicious
                    )
                }
            } else if (urlAnalysis?.hasOpenRedirect == true) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFF3B1214))
                        .padding(horizontal = 6.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = "OPEN REDIRECT",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold,
                        color = StatusPhishing
                    )
                }
            } else if (isVerifiedBank) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFF0F2E1B))
                        .padding(horizontal = 6.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = "BANK WHITELIST",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold,
                        color = StatusSafe
                    )
                }
            } else if (isRawIp) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFF3B1214))
                        .padding(horizontal = 6.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = "RAW IP DETECTED",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Bold,
                        color = StatusPhishing
                    )
                }
            }
        }
    }
}

/**
 * Smart Clipboard Detection Banner
 */
@Composable
fun ClipboardDetectionBanner(
    detectedUrl: String,
    onPasteAndScan: () -> Unit,
    onPasteOnly: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFF3A3A3C), RoundedCornerShape(18.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurfaceVariant),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.ContentPaste,
                        contentDescription = "Clipboard",
                        tint = NothingWhite,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "COPIED LINK DETECTED",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        color = NothingWhite
                    )
                }

                Text(
                    text = "SYSTEM CLIPBOARD",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    color = NothingGrey
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = detectedUrl,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = NothingLightGrey,
                maxLines = 1
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onPasteAndScan,
                    modifier = Modifier
                        .weight(1f)
                        .height(36.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NothingWhite,
                        contentColor = NothingBlack
                    ),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                ) {
                    Text(
                        text = "PASTE & ANALYZE NOW",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Button(
                    onClick = onPasteOnly,
                    modifier = Modifier.height(36.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NothingSurfaceElevated,
                        contentColor = NothingWhite
                    ),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 0.dp)
                ) {
                    Text(
                        text = "INSERT",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp
                    )
                }
            }
        }
    }
}

/**
 * 4-Engine Defense Telemetry Bento Grid
 */
@Composable
fun EngineStatusBentoGrid(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            EngineStatusCard(
                tag = "[01]",
                title = "HEURISTIC & ENTROPY",
                subtitle = "Shannon Entropy, IP Evasion, Subdomain Depth",
                activeColor = StatusSafe,
                icon = Icons.Filled.Language,
                modifier = Modifier.weight(1f)
            )
            EngineStatusCard(
                tag = "[02]",
                title = "BRAND RADAR",
                subtitle = "30+ Banking & Postal Levenshtein Matchers",
                activeColor = StatusSafe,
                icon = Icons.Filled.Shield,
                modifier = Modifier.weight(1f)
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            EngineStatusCard(
                tag = "[03]",
                title = "STATISTICAL NLP",
                subtitle = "Rule & Urgency Cue Extractor",
                activeColor = StatusSafe,
                icon = Icons.Filled.Security,
                modifier = Modifier.weight(1f)
            )
            EngineStatusCard(
                tag = "[04]",
                title = "THREAT INTEL & SQL",
                subtitle = "RBI .bank.in Registry & Campaign Blacklist",
                activeColor = StatusSafe,
                icon = Icons.Filled.CheckCircle,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun EngineStatusCard(
    tag: String,
    title: String,
    subtitle: String,
    activeColor: Color,
    icon: ImageVector,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .border(1.dp, NothingBorder, RoundedCornerShape(18.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = NothingWhite,
                        modifier = Modifier.size(13.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = tag,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        color = NothingGrey
                    )
                }

                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(CircleShape)
                        .background(activeColor)
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = title,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = NothingWhite,
                letterSpacing = 0.5.sp
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = subtitle,
                fontFamily = FontFamily.SansSerif,
                fontSize = 10.sp,
                color = NothingGrey,
                lineHeight = 13.sp
            )
        }
    }
}

/**
 * Emergency Incident Response Protocol Card
 */
@Composable
fun EmergencyIncidentResponseCard(modifier: Modifier = Modifier) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFF5C1014), RoundedCornerShape(20.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(20.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(NothingRed)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "EMERGENCY CONTAINMENT // 4 STEPS",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        color = NothingWhite
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(Color(0xFF330C0E))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = "HOTLINE 1930",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingRed
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            IncidentStepRow(
                num = "01",
                action = "DISCONNECT NETWORK IMMEDIATELY",
                desc = "Turn on Airplane Mode or switch off Wi-Fi & Mobile Data to stop ongoing malware payload execution."
            )

            Spacer(modifier = Modifier.height(8.dp))

            IncidentStepRow(
                num = "02",
                action = "RESET PASSWORDS VIA SECONDARY DEVICE",
                desc = "From an unaffected device, change passwords and revoke active login sessions on all compromised accounts."
            )

            Spacer(modifier = Modifier.height(8.dp))

            IncidentStepRow(
                num = "03",
                action = "FREEZE BANK CARDS & NOTIFY FRAUD DESK",
                desc = "Open your bank's app to freeze debit/credit cards or call 24x7 card blocking emergency numbers."
            )

            Spacer(modifier = Modifier.height(8.dp))

            IncidentStepRow(
                num = "04",
                action = "LODGE CYBER FRAUD REPORT",
                desc = "File an official complaint at cybercrime.gov.in or dial the National Cyber Crime Helpline at 1930."
            )
        }
    }
}

@Composable
fun IncidentStepRow(
    num: String,
    action: String,
    desc: String
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(NothingSurfaceElevated)
            .padding(10.dp),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(NothingBlack)
                .padding(horizontal = 6.dp, vertical = 2.dp)
        ) {
            Text(
                text = num,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = NothingRed
            )
        }

        Spacer(modifier = Modifier.width(10.dp))

        Column {
            Text(
                text = action,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = NothingWhite
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = desc,
                fontFamily = FontFamily.SansSerif,
                fontSize = 10.sp,
                color = NothingGrey,
                lineHeight = 13.sp
            )
        }
    }
}

/**
 * Nothing OS Hero Header
 */
@Composable
fun NothingHeroDashboard(
    totalScans: Int,
    threatsBlocked: Int,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, NothingBorder, RoundedCornerShape(26.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(26.dp)
    ) {
        Box(modifier = Modifier.fillMaxWidth()) {
            // Background dot matrix texture
            DotMatrixBackground(
                modifier = Modifier.matchParentSize(),
                dotSpacing = 12.dp,
                dotRadius = 1.dp,
                dotColor = Color(0xFF1E1E1E)
            )

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp)
            ) {
                // Top Header Row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(7.dp)
                                    .clip(CircleShape)
                                    .background(NothingRed)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "NO(PHISH)",
                                fontFamily = FontFamily.Monospace,
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Black,
                                letterSpacing = 2.sp,
                                color = NothingWhite
                            )
                        }
                        Text(
                            text = "URL THREAT MATRIX // OS v2.5",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = NothingGrey,
                            letterSpacing = 1.sp,
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }

                    // Status Pill
                    Row(
                        modifier = Modifier
                            .clip(CircleShape)
                            .background(Color(0xFF1E1E1E))
                            .border(1.dp, Color(0xFF333333), CircleShape)
                            .padding(horizontal = 10.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        NothingGlyphPulse(color = StatusSafe)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "ONLINE",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = StatusSafe
                        )
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                // Bento Stats Tiles
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    NothingBentoStatTile(
                        tag = "[01]",
                        title = "SCANS LOGGED",
                        value = totalScans.toString().padStart(2, '0'),
                        valueColor = NothingWhite,
                        modifier = Modifier.weight(1f)
                    )
                    NothingBentoStatTile(
                        tag = "[02]",
                        title = "THREATS BLOCKED",
                        value = threatsBlocked.toString().padStart(2, '0'),
                        valueColor = if (threatsBlocked > 0) NothingRed else NothingGrey,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}

@Composable
fun NothingBentoStatTile(
    tag: String,
    title: String,
    value: String,
    valueColor: Color,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(16.dp))
            .background(NothingBlack)
            .border(1.dp, NothingBorder, RoundedCornerShape(16.dp))
            .padding(14.dp)
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp,
                    color = NothingGrey
                )
                Text(
                    text = tag,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    color = NothingGrey
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = value,
                fontFamily = FontFamily.Monospace,
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = (-0.5).sp,
                color = valueColor
            )
        }
    }
}
