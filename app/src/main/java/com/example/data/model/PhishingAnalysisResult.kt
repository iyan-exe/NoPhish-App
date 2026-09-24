package com.example.data.model

import androidx.annotation.Keep
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@Keep
enum class EvidenceSeverity {
    CRITICAL, HIGH, MEDIUM, LOW, NEUTRAL
}

@Keep
@JsonClass(generateAdapter = true)
data class EvidenceItem(
    @param:Json(name = "category")
    val category: String = "General",
    @param:Json(name = "title")
    val title: String = "",
    @param:Json(name = "description")
    val description: String = "",
    @param:Json(name = "severity")
    val severity: EvidenceSeverity = EvidenceSeverity.MEDIUM,
    @param:Json(name = "indicator")
    val indicator: String = ""
)

@Keep
@JsonClass(generateAdapter = true)
data class PhishingAnalysisResult(
    @param:Json(name = "url")
    val url: String = "",
    @param:Json(name = "status")
    val status: String = "LOW RISK", // "LOW RISK", "SUSPICIOUS", "HIGH RISK", "LIKELY PHISHING", "BLOCKED"
    @param:Json(name = "risk_score")
    val riskScore: Int = 0, // 0 to 100
    @param:Json(name = "detected_threats")
    val detectedThreats: List<String> = emptyList(),
    @param:Json(name = "analysis_breakdown")
    val analysisBreakdown: AnalysisBreakdown = AnalysisBreakdown(),
    @param:Json(name = "user_explanation")
    val userExplanation: String = "",
    @param:Json(name = "recommendation")
    val recommendation: String = "",
    @param:Json(name = "evidence_list")
    val evidenceList: List<EvidenceItem> = emptyList(),
    @param:Json(name = "engine_telemetry")
    val engineTelemetry: EngineTelemetry = EngineTelemetry(),
    val rawJson: String = "",
    val scannedAt: Long = System.currentTimeMillis(),
    val contextText: String = ""
)

@Keep
@JsonClass(generateAdapter = true)
data class EngineTelemetry(
    @param:Json(name = "ml_probability")
    val mlProbability: Float = 0.0f,
    @param:Json(name = "ml_confidence")
    val mlConfidence: Float = 0.0f,
    @param:Json(name = "ml_top_contributors")
    val mlTopContributors: List<String> = emptyList(),
    @param:Json(name = "rag_top_match")
    val ragTopMatch: String? = null,
    @param:Json(name = "rag_cosine_similarity")
    val ragCosineSimilarity: Float = 0.0f,
    @param:Json(name = "rag_matched_iocs")
    val ragMatchedIocs: List<String> = emptyList(),
    @param:Json(name = "nlp_urgency_score")
    val nlpUrgencyScore: Int = 0,
    @param:Json(name = "nlp_imperative_ratio")
    val nlpImperativeRatio: Float = 0.0f,
    @param:Json(name = "nlp_tactics")
    val nlpTactics: List<String> = emptyList(),
    @param:Json(name = "shannon_entropy")
    val shannonEntropy: Float = 0.0f,
    @param:Json(name = "url_length")
    val urlLength: Int = 0,
    @param:Json(name = "input_type")
    val inputType: String = "URL",
    @param:Json(name = "model_version")
    val modelVersion: String = "v2.0.0-multimodal"
)

@Keep
@JsonClass(generateAdapter = true)
data class AnalysisBreakdown(
    @param:Json(name = "url_structure")
    val urlStructure: String = "Normal URL structure",
    @param:Json(name = "nlp_urgency_check")
    val nlpUrgencyCheck: String = "No urgency pressure detected",
    @param:Json(name = "brand_impersonation")
    val brandImpersonation: String = "No brand mismatch found",
    @param:Json(name = "whitelist_status")
    val whitelistStatus: String = "No Match", // "Match Found" or "No Match"
    @param:Json(name = "html_analysis")
    val htmlAnalysis: String = "No webpage content provided",
    @param:Json(name = "redirect_chain")
    val redirectChain: String = "Direct destination (no redirects detected)",
    @param:Json(name = "visual_analysis")
    val visualAnalysis: String = "No screenshot analyzed"
)

enum class ScanStatus(val label: String, val badgeColor: Long) {
    LOW_RISK("LOW RISK", 0xFF00E676),
    SUSPICIOUS("SUSPICIOUS", 0xFFFFB300),
    HIGH_RISK("HIGH RISK", 0xFFFF5722),
    LIKELY_PHISHING("LIKELY PHISHING", 0xFFD50000),
    BLOCKED("BLOCKED", 0xFF880E4F),
    SAFE("LOW RISK", 0xFF00E676), // Backward compatibility
    PHISHING("LIKELY PHISHING", 0xFFD50000); // Backward compatibility

    companion object {
        fun fromScore(score: Int, isBlocked: Boolean = false): ScanStatus {
            return when {
                isBlocked -> BLOCKED
                score >= 76 -> LIKELY_PHISHING
                score >= 51 -> HIGH_RISK
                score >= 21 -> SUSPICIOUS
                else -> LOW_RISK
            }
        }

        fun fromString(value: String): ScanStatus {
            val v = value.uppercase().trim()
            return when {
                v.contains("BLOCK") -> BLOCKED
                v.contains("LIKELY") || (v.contains("PHISH") && !v.contains("LOW")) -> LIKELY_PHISHING
                v.contains("HIGH") -> HIGH_RISK
                v.contains("SUSP") -> SUSPICIOUS
                v.contains("SAFE") || v.contains("LOW") -> LOW_RISK
                else -> LOW_RISK
            }
        }
    }
}

