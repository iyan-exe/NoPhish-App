package com.example.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val url: String,
    val contextText: String,
    val status: String,
    val riskScore: Int,
    val detectedThreatsJson: String,
    val urlStructureBreakdown: String,
    val nlpUrgencyBreakdown: String,
    val brandImpersonationBreakdown: String,
    val whitelistStatus: String,
    val userExplanation: String,
    val rawJson: String,
    val scannedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "whitelist_domains")
data class WhitelistEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val domain: String,
    val brandName: String,
    val category: String, // "Government", "Financial", "Technology", "E-Commerce", "Custom"
    val isVerified: Boolean = true,
    val addedAt: Long = System.currentTimeMillis()
)

data class PresetScenario(
    val title: String,
    val category: String,
    val url: String,
    val contextText: String,
    val description: String
)
