package com.example.data.model

import androidx.annotation.Keep
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@Keep
@JsonClass(generateAdapter = true)
data class PhishingAnalysisResult(
    @param:Json(name = "url")
    val url: String = "",
    @param:Json(name = "status")
    val status: String = "Safe", // "Safe", "Suspicious", "Phishing"
    @param:Json(name = "risk_score")
    val riskScore: Int = 0, // 0 to 100
    @param:Json(name = "detected_threats")
    val detectedThreats: List<String> = emptyList(),
    @param:Json(name = "analysis_breakdown")
    val analysisBreakdown: AnalysisBreakdown = AnalysisBreakdown(),
    @param:Json(name = "user_explanation")
    val userExplanation: String = "",
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
    @param:Json(name = "model_version")
    val modelVersion: String = "v1.1.0-stratified"
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
    val whitelistStatus: String = "No Match" // "Match Found" or "No Match"
)

enum class ScanStatus(val label: String) {
    SAFE("Safe"),
    SUSPICIOUS("Suspicious"),
    PHISHING("Phishing");

    companion object {
        fun fromString(value: String): ScanStatus {
            return entries.firstOrNull { it.label.equals(value, ignoreCase = true) } ?: when {
                value.contains("phish", ignoreCase = true) -> PHISHING
                value.contains("susp", ignoreCase = true) -> SUSPICIOUS
                else -> SAFE
            }
        }
    }
}
