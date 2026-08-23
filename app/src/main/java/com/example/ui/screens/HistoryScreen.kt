package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Launch
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.ScanHistoryEntity
import com.example.ui.MainViewModel
import com.example.ui.components.NothingSectionHeader
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
import com.example.ui.theme.StatusPhishingBorder
import com.example.ui.theme.StatusPhishingContainer
import com.example.ui.theme.StatusSafe
import com.example.ui.theme.StatusSafeBorder
import com.example.ui.theme.StatusSafeContainer
import com.example.ui.theme.StatusSuspicious
import com.example.ui.theme.StatusSuspiciousBorder
import com.example.ui.theme.StatusSuspiciousContainer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HistoryScreen(
    viewModel: MainViewModel,
    onNavigateToScan: () -> Unit,
    modifier: Modifier = Modifier
) {
    val historyList by viewModel.scanHistory.collectAsState()
    var selectedFilter by remember { mutableStateOf("ALL") }
    var showClearDialog by remember { mutableStateOf(false) }

    val filteredList = when (selectedFilter) {
        "PHISHING" -> historyList.filter { it.status.equals("Phishing", ignoreCase = true) }
        "SUSPICIOUS" -> historyList.filter { it.status.equals("Suspicious", ignoreCase = true) }
        "SAFE" -> historyList.filter { it.status.equals("Safe", ignoreCase = true) }
        else -> historyList
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(NothingBlack)
            .padding(horizontal = 16.dp)
    ) {
        Spacer(modifier = Modifier.height(12.dp))

        // Top Bar
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
                        text = "AUDIT TRAIL",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 2.sp,
                        color = NothingWhite
                    )
                }
                Text(
                    text = "${historyList.size} URL EVALUATIONS STORED IN ROOM DB",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    color = NothingGrey,
                    letterSpacing = 0.8.sp,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            if (historyList.isNotEmpty()) {
                IconButton(
                    onClick = { showClearDialog = true },
                    modifier = Modifier.testTag("clear_history_button")
                ) {
                    Icon(
                        imageVector = Icons.Filled.DeleteSweep,
                        contentDescription = "Clear History",
                        tint = NothingWhite
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Nothing OS Filter Pills
        val filters = listOf("ALL", "PHISHING", "SUSPICIOUS", "SAFE")
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            items(filters) { filter ->
                val isSelected = selectedFilter == filter
                val count = when (filter) {
                    "PHISHING" -> historyList.count { it.status.equals("Phishing", ignoreCase = true) }
                    "SUSPICIOUS" -> historyList.count { it.status.equals("Suspicious", ignoreCase = true) }
                    "SAFE" -> historyList.count { it.status.equals("Safe", ignoreCase = true) }
                    else -> historyList.size
                }

                Box(
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(if (isSelected) NothingWhite else NothingSurface)
                        .border(1.dp, if (isSelected) NothingWhite else NothingBorder, CircleShape)
                        .clickable { selectedFilter = filter }
                        .padding(horizontal = 14.dp, vertical = 7.dp)
                ) {
                    Text(
                        text = "$filter ($count)",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                        color = if (isSelected) NothingBlack else NothingGrey
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // History List
        if (filteredList.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(
                        modifier = Modifier
                            .size(54.dp)
                            .clip(CircleShape)
                            .background(NothingSurface)
                            .border(1.dp, NothingBorder, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "∅",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 24.sp,
                            color = NothingGrey
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "NO AUDIT LOGS FOUND",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.2.sp,
                        color = NothingWhite
                    )
                    Text(
                        text = "Run a URL threat analysis to generate logs",
                        fontFamily = FontFamily.SansSerif,
                        fontSize = 11.sp,
                        color = NothingGrey,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 80.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                items(filteredList, key = { it.id }) { item ->
                    NothingHistoryCard(
                        item = item,
                        onClick = {
                            viewModel.loadHistoryItem(item)
                            onNavigateToScan()
                        },
                        onDelete = { viewModel.deleteHistoryItem(item.id) }
                    )
                }
            }
        }
    }

    // Confirmation dialog
    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            containerColor = NothingSurface,
            shape = RoundedCornerShape(22.dp),
            title = {
                Text(
                    text = "PURGE AUDIT TRAIL?",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = NothingWhite
                )
            },
            text = {
                Text(
                    text = "This will permanently delete all scan records from the local Room database.",
                    fontFamily = FontFamily.SansSerif,
                    fontSize = 12.sp,
                    color = NothingGrey
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.clearAllHistory()
                        showClearDialog = false
                    }
                ) {
                    Text(
                        text = "PURGE ALL",
                        fontFamily = FontFamily.Monospace,
                        color = NothingRed,
                        fontWeight = FontWeight.Bold
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) {
                    Text(
                        text = "CANCEL",
                        fontFamily = FontFamily.Monospace,
                        color = NothingWhite
                    )
                }
            }
        )
    }
}

@Composable
fun NothingHistoryCard(
    item: ScanHistoryEntity,
    onClick: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isPhishing = item.status.equals("Phishing", ignoreCase = true)
    val isSuspicious = item.status.equals("Suspicious", ignoreCase = true)

    val (badgeBg, badgeBorder, badgeColor, glyph) = when {
        isPhishing -> Tuple4(StatusPhishingContainer, StatusPhishingBorder, StatusPhishing, "▲")
        isSuspicious -> Tuple4(StatusSuspiciousContainer, StatusSuspiciousBorder, StatusSuspicious, "◆")
        else -> Tuple4(StatusSafeContainer, StatusSafeBorder, StatusSafe, "●")
    }

    val dateFormat = remember { SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault()) }
    val formattedDate = remember(item.scannedAt) { dateFormat.format(Date(item.scannedAt)) }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, NothingBorder, RoundedCornerShape(20.dp)),
        colors = CardDefaults.cardColors(containerColor = NothingSurface),
        shape = RoundedCornerShape(20.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onClick() }
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Status Pill
                Row(
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(badgeBg)
                        .border(1.dp, badgeBorder, CircleShape)
                        .padding(horizontal = 8.dp, vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = glyph,
                        fontSize = 9.sp,
                        color = badgeColor
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = item.status.uppercase(),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = badgeColor
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = formattedDate,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = NothingGrey
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    IconButton(
                        onClick = onDelete,
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = "Delete Record",
                            tint = NothingGrey,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // URL
            Text(
                text = item.url,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = NothingWhite,
                maxLines = 1
            )

            Spacer(modifier = Modifier.height(6.dp))

            // Risk Score and Tap to Inspect
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "SCORE: ${item.riskScore} / 100",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = badgeColor
                )

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "INSPECT",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = NothingWhite
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.Launch,
                        contentDescription = "Inspect",
                        tint = NothingWhite,
                        modifier = Modifier.size(12.dp)
                    )
                }
            }
        }
    }
}

private data class Tuple4<A, B, C, D>(
    val a: A, val b: B, val c: C, val d: D
)
