package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.KnownPhishingThreat
import com.example.data.model.ThreatDatabase
import com.example.data.model.WhitelistEntity
import com.example.ui.MainViewModel
import com.example.ui.theme.NothingBlack
import com.example.ui.theme.NothingBorder
import com.example.ui.theme.NothingBorderSubtle
import com.example.ui.theme.NothingGrey
import com.example.ui.theme.NothingLightGrey
import com.example.ui.theme.NothingRed
import com.example.ui.theme.NothingSurface
import com.example.ui.theme.NothingSurfaceElevated
import com.example.ui.theme.NothingWhite
import com.example.ui.theme.StatusPhishing
import com.example.ui.theme.StatusPhishingContainer
import com.example.ui.theme.StatusSafe

enum class IntelSection {
    FAKE_WEBSITES,
    SQL_WHITELIST
}

@Composable
fun ThreatIntelScreen(
    viewModel: MainViewModel,
    onNavigateToScan: () -> Unit,
    modifier: Modifier = Modifier
) {
    var currentSection by remember { mutableStateOf(IntelSection.FAKE_WEBSITES) }
    val knownThreats by viewModel.knownThreats.collectAsState()
    val threatQuery by viewModel.threatSearchQuery.collectAsState()
    val selectedThreatCategory by viewModel.selectedThreatCategory.collectAsState()

    val whitelist by viewModel.whitelistDomains.collectAsState()
    var whitelistCategory by remember { mutableStateOf("ALL") }
    var showAddDialog by remember { mutableStateOf(false) }

    val whitelistCategories = listOf("ALL", "Government", "Financial", "Technology", "Logistics", "E-Commerce", "Custom")

    val filteredWhitelist = if (whitelistCategory == "ALL") {
        whitelist
    } else {
        whitelist.filter { it.category.equals(whitelistCategory, ignoreCase = true) }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(NothingBlack)
            .padding(horizontal = 16.dp)
    ) {
        Spacer(modifier = Modifier.height(12.dp))

        // Top Header
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
                        text = "THREAT MATRIX",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 2.sp,
                        color = NothingWhite
                    )
                }
                Text(
                    text = "${ThreatDatabase.KNOWN_FAKE_WEBSITES.size} FAKE SITES • ${whitelist.size} VERIFIED REPOSITORIES",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    color = NothingGrey,
                    letterSpacing = 0.8.sp,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            if (currentSection == IntelSection.SQL_WHITELIST) {
                Button(
                    onClick = { showAddDialog = true },
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NothingWhite,
                        contentColor = NothingBlack
                    ),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                    modifier = Modifier
                        .height(34.dp)
                        .testTag("add_whitelist_button")
                ) {
                    Icon(
                        imageVector = Icons.Filled.Add,
                        contentDescription = "Add",
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "ADD",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Segmented Switcher: [FAKE SITES FEED] vs [SQL WHITELIST]
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(CircleShape)
                .background(NothingSurface)
                .border(1.dp, NothingBorder, CircleShape)
                .padding(3.dp)
        ) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(CircleShape)
                    .background(if (currentSection == IntelSection.FAKE_WEBSITES) NothingWhite else Color.Transparent)
                    .clickable { currentSection = IntelSection.FAKE_WEBSITES }
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Warning,
                        contentDescription = null,
                        tint = if (currentSection == IntelSection.FAKE_WEBSITES) NothingBlack else StatusPhishing,
                        modifier = Modifier.size(13.dp)
                    )
                    Spacer(modifier = Modifier.width(5.dp))
                    Text(
                        text = "FAKE SITES (${knownThreats.size})",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (currentSection == IntelSection.FAKE_WEBSITES) NothingBlack else NothingGrey
                    )
                }
            }

            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(CircleShape)
                    .background(if (currentSection == IntelSection.SQL_WHITELIST) NothingWhite else Color.Transparent)
                    .clickable { currentSection = IntelSection.SQL_WHITELIST }
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Shield,
                        contentDescription = null,
                        tint = if (currentSection == IntelSection.SQL_WHITELIST) NothingBlack else StatusSafe,
                        modifier = Modifier.size(13.dp)
                    )
                    Spacer(modifier = Modifier.width(5.dp))
                    Text(
                        text = "WHITELIST (${whitelist.size})",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (currentSection == IntelSection.SQL_WHITELIST) NothingBlack else NothingGrey
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        when (currentSection) {
            IntelSection.FAKE_WEBSITES -> {
                // Search Input for Fake Websites
                OutlinedTextField(
                    value = threatQuery,
                    onValueChange = { viewModel.onThreatSearchQueryChange(it) },
                    placeholder = {
                        Text(
                            "Search fake domains, brands, or traps...",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = NothingGrey
                        )
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Filled.Search,
                            contentDescription = "Search",
                            tint = NothingGrey,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    trailingIcon = {
                        if (threatQuery.isNotEmpty()) {
                            IconButton(onClick = { viewModel.onThreatSearchQueryChange("") }) {
                                Icon(
                                    imageVector = Icons.Filled.Close,
                                    contentDescription = "Clear",
                                    tint = NothingGrey,
                                    modifier = Modifier.size(14.dp)
                                )
                            }
                        }
                    },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = NothingWhite,
                        unfocusedBorderColor = NothingBorder,
                        focusedContainerColor = NothingSurface,
                        unfocusedContainerColor = NothingSurface,
                        focusedTextColor = NothingWhite,
                        unfocusedTextColor = NothingWhite
                    ),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .testTag("threat_search_input")
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Threat Category Filter Pills
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    items(ThreatDatabase.THREAT_CATEGORIES) { cat ->
                        val isSelected = selectedThreatCategory == cat
                        Box(
                            modifier = Modifier
                                .clip(CircleShape)
                                .background(if (isSelected) NothingWhite else NothingSurface)
                                .border(1.dp, if (isSelected) NothingWhite else NothingBorder, CircleShape)
                                .clickable { viewModel.onThreatCategorySelect(cat) }
                                .padding(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = cat.uppercase(),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSelected) NothingBlack else NothingGrey
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Fake Sites Feed List
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 80.dp),
                    modifier = Modifier.fillMaxSize()
                ) {
                    if (knownThreats.isEmpty()) {
                        item {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 36.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = "NO THREAT MATCHES FOUND",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp,
                                    color = NothingGrey
                                )
                            }
                        }
                    } else {
                        items(knownThreats, key = { it.id }) { threat ->
                            FakeWebsiteThreatCard(
                                threat = threat,
                                onScanThis = {
                                    viewModel.loadThreatScenario(threat)
                                    viewModel.analyze()
                                    onNavigateToScan()
                                }
                            )
                        }
                    }
                }
            }

            IntelSection.SQL_WHITELIST -> {
                // Category Filter Pills for Whitelist
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    items(whitelistCategories) { cat ->
                        val isSelected = whitelistCategory == cat
                        Box(
                            modifier = Modifier
                                .clip(CircleShape)
                                .background(if (isSelected) NothingWhite else NothingSurface)
                                .border(1.dp, if (isSelected) NothingWhite else NothingBorder, CircleShape)
                                .clickable { whitelistCategory = cat }
                                .padding(horizontal = 14.dp, vertical = 7.dp)
                        ) {
                            Text(
                                text = cat.uppercase(),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSelected) NothingBlack else NothingGrey
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // Whitelist List
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 80.dp),
                    modifier = Modifier.fillMaxSize()
                ) {
                    items(filteredWhitelist, key = { it.id }) { domainItem ->
                        NothingWhitelistItemCard(item = domainItem)
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        AddWhitelistDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { domain, brand, category ->
                viewModel.addCustomWhitelistDomain(domain, brand, category)
                showAddDialog = false
            }
        )
    }
}

/**
 * Rich Threat Intelligence Card for Fake Websites with IoCs & One-tap Live Scan.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun FakeWebsiteThreatCard(
    threat: KnownPhishingThreat,
    onScanThis: () -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(targetValue = if (isPressed) 0.98f else 1f, label = "pressScale")

    Card(
        modifier = modifier
            .fillMaxWidth()
            .scale(scale)
            .border(1.dp, NothingBorder, RoundedCornerShape(18.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp)
        ) {
            // Header Row: Category Badge, Threat Title & Severity
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
                            .background(StatusPhishing)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = threat.category.uppercase(),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingRed
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(StatusPhishingContainer)
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = "RISK ${threat.riskScore}%",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Black,
                        color = StatusPhishing
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Title
            Text(
                text = threat.title,
                fontFamily = FontFamily.SansSerif,
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = NothingWhite
            )

            // Fake Domain
            Text(
                text = "FAKE: ${threat.fakeDomain}",
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = NothingRed,
                modifier = Modifier.padding(top = 2.dp)
            )

            // Target Brand
            Text(
                text = "TARGET: ${threat.targetBrand}",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = NothingGrey,
                modifier = Modifier.padding(top = 1.dp)
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Expandable Intelligence Section
            AnimatedVisibility(
                visible = expanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(NothingBlack)
                        .border(1.dp, NothingBorderSubtle, RoundedCornerShape(12.dp))
                        .padding(12.dp)
                ) {
                    // Attack Vector
                    Text(
                        text = "ATTACK MECHANISM",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingGrey
                    )
                    Text(
                        text = threat.attackVector,
                        fontFamily = FontFamily.SansSerif,
                        fontSize = 11.sp,
                        color = NothingWhite,
                        modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
                    )

                    // Deception Technique
                    Text(
                        text = "DECEPTION STRATEGY",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingGrey
                    )
                    Text(
                        text = threat.deceptionTechnique,
                        fontFamily = FontFamily.SansSerif,
                        fontSize = 11.sp,
                        color = NothingLightGrey,
                        lineHeight = 15.sp,
                        modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
                    )

                    // Indicators of Compromise
                    Text(
                        text = "INDICATORS OF COMPROMISE (IoCs)",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingGrey
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        threat.indicatorsOfCompromise.forEach { ioc ->
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(NothingSurfaceElevated)
                                    .border(1.dp, NothingBorderSubtle, RoundedCornerShape(6.dp))
                                    .padding(horizontal = 8.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = ioc,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 9.sp,
                                    color = NothingWhite
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Sample Message Lure
                    Text(
                        text = "TRAP MESSAGE LURE",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingGrey
                    )
                    Text(
                        text = "\"${threat.sampleMessage}\"",
                        fontFamily = FontFamily.SansSerif,
                        fontSize = 11.sp,
                        color = NothingGrey,
                        lineHeight = 15.sp,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Action Buttons: Expand details & Test/Scan in Scanner
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    modifier = Modifier
                        .clip(CircleShape)
                        .clickable { expanded = !expanded }
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = if (expanded) "HIDE INTEL" else "VIEW INTEL",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingLightGrey
                    )
                    Icon(
                        imageVector = if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = "Expand",
                        tint = NothingLightGrey,
                        modifier = Modifier.size(16.dp)
                    )
                }

                Button(
                    onClick = onScanThis,
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NothingWhite,
                        contentColor = NothingBlack
                    ),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 4.dp),
                    modifier = Modifier.height(32.dp)
                ) {
                    Text(
                        text = "TEST IN SCANNER",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                        contentDescription = "Scan",
                        modifier = Modifier.size(12.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun NothingWhitelistItemCard(
    item: WhitelistEntity,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, NothingBorder, RoundedCornerShape(18.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(18.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                // Verified green dot
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(StatusSafe)
                )

                Spacer(modifier = Modifier.width(10.dp))

                Column {
                    Text(
                        text = item.domain,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingWhite
                    )
                    Text(
                        text = "${item.brandName} // ${item.category}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = NothingGrey
                    )
                }
            }

            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(NothingSurfaceElevated)
                    .border(1.dp, NothingBorderSubtle, RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 3.dp)
            ) {
                Text(
                    text = item.category.uppercase(),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.8.sp,
                    color = NothingLightGrey
                )
            }
        }
    }
}

@Composable
fun AddWhitelistDialog(
    onDismiss: () -> Unit,
    onAdd: (domain: String, brand: String, category: String) -> Unit
) {
    var domain by remember { mutableStateOf("") }
    var brand by remember { mutableStateOf("") }
    var category by remember { mutableStateOf("Custom") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = NothingSurface,
        shape = RoundedCornerShape(22.dp),
        title = {
            Text(
                text = "ADD TRUSTED DOMAIN",
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = NothingWhite
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = domain,
                    onValueChange = { domain = it },
                    label = { Text("Domain (e.g., myschool.edu)", fontFamily = FontFamily.Monospace, fontSize = 11.sp) },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = NothingWhite,
                        unfocusedBorderColor = NothingBorder,
                        focusedContainerColor = NothingBlack,
                        unfocusedContainerColor = NothingBlack,
                        focusedTextColor = NothingWhite,
                        unfocusedTextColor = NothingWhite
                    ),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("whitelist_domain_input")
                )
                OutlinedTextField(
                    value = brand,
                    onValueChange = { brand = it },
                    label = { Text("Brand / Entity Name", fontFamily = FontFamily.Monospace, fontSize = 11.sp) },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = NothingWhite,
                        unfocusedBorderColor = NothingBorder,
                        focusedContainerColor = NothingBlack,
                        unfocusedContainerColor = NothingBlack,
                        focusedTextColor = NothingWhite,
                        unfocusedTextColor = NothingWhite
                    ),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = category,
                    onValueChange = { category = it },
                    label = { Text("Category (e.g., Education, Custom)", fontFamily = FontFamily.Monospace, fontSize = 11.sp) },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = NothingWhite,
                        unfocusedBorderColor = NothingBorder,
                        focusedContainerColor = NothingBlack,
                        unfocusedContainerColor = NothingBlack,
                        focusedTextColor = NothingWhite,
                        unfocusedTextColor = NothingWhite
                    ),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (domain.isNotBlank()) {
                        onAdd(domain, brand, category)
                    }
                },
                enabled = domain.isNotBlank(),
                shape = CircleShape,
                colors = ButtonDefaults.buttonColors(
                    containerColor = NothingWhite,
                    contentColor = NothingBlack
                )
            ) {
                Text("ADD DOMAIN", fontFamily = FontFamily.Monospace, fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("CANCEL", fontFamily = FontFamily.Monospace, color = NothingGrey)
            }
        }
    )
}
