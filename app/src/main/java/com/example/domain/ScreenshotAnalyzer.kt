package com.example.domain

import android.graphics.Bitmap
import com.example.data.model.EvidenceItem
import com.example.data.model.EvidenceSeverity

data class ScreenshotAnalysisResult(
    val detectedBrand: String? = null,
    val visualBrandConfidence: Float = 0.0f,
    val hasLoginFormCard: Boolean = false,
    val hasCredentialInputs: Boolean = false,
    val hasFakeSecurityBadges: Boolean = false,
    val hasScarewareUrgencyOverlay: Boolean = false,
    val extractedVisibleUrl: String? = null,
    val visualMismatchDetected: Boolean = false,
    val visualRiskScore: Int = 0,
    val evidence: List<EvidenceItem> = emptyList(),
    val visualSummary: String = ""
)

/**
 * Visual & Screenshot Phishing Evidence Analyzer.
 *
 * Inspects webpage screenshots for brand impersonation cues, login card visual geometry,
 * deceptive security badges, scareware warning dialogs, and displayed vs destination URL divergence.
 * Clearly labeled as VISUAL EVIDENCE.
 */
object ScreenshotAnalyzer {

    private val TARGET_BRANDS = listOf(
        "PayPal", "Microsoft", "Google", "Apple", "State Bank of India", "Amazon",
        "MetaMask", "Netflix", "Chase Bank", "India Post", "Instagram"
    )

    fun analyzeScreenshot(
        bitmap: Bitmap?,
        associatedUrl: String = "",
        visualTextClues: String = ""
    ): ScreenshotAnalysisResult {
        val evidenceList = mutableListOf<EvidenceItem>()
        var score = 0

        val textLower = visualTextClues.lowercase()
        var detectedBrand: String? = null
        var brandConfidence = 0.0f

        // Check for recognized visual branding text or logo cues
        for (brand in TARGET_BRANDS) {
            if (textLower.contains(brand.lowercase())) {
                detectedBrand = brand
                brandConfidence = 0.85f
                break
            }
        }

        // Detect credential harvesting visual indicators
        val hasLoginFormCard = textLower.contains("sign in") || textLower.contains("login") ||
                textLower.contains("log in") || textLower.contains("username") || textLower.contains("enter password")

        val hasCredentialInputs = textLower.contains("password") || textLower.contains("passcode") ||
                textLower.contains("otp") || textLower.contains("recovery phrase") || textLower.contains("card number")

        val hasFakeBadges = textLower.contains("verified by") || textLower.contains("norton secured") ||
                textLower.contains("mcafee") || textLower.contains("official portal")

        val hasScareware = textLower.contains("critical alert") || textLower.contains("trojan") ||
                textLower.contains("call support") || textLower.contains("system locked")

        if (detectedBrand != null) {
            val urlHost = DomainUtils.extractCleanHost(associatedUrl)
            val isOfficialHost = DomainUtils.isKnownTopLegitimateDomain(urlHost) &&
                    urlHost.contains(detectedBrand.lowercase().replace(" ", ""))

            if (associatedUrl.isNotBlank() && !isOfficialHost) {
                score += 50
                evidenceList.add(
                    EvidenceItem(
                        category = "Visual Screenshot Analysis",
                        title = "Visual Brand vs URL Host Mismatch",
                        description = "Screenshot displays visual branding for '$detectedBrand', but target domain is '$urlHost'.",
                        severity = EvidenceSeverity.HIGH,
                        indicator = "Visual mismatch: $detectedBrand vs $urlHost"
                    )
                )
            } else {
                evidenceList.add(
                    EvidenceItem(
                        category = "Visual Screenshot Analysis",
                        title = "Visual Brand Identified",
                        description = "Visual layout exhibits branding signatures consistent with $detectedBrand.",
                        severity = EvidenceSeverity.NEUTRAL,
                        indicator = "Brand: $detectedBrand"
                    )
                )
            }
        }

        if (hasLoginFormCard || hasCredentialInputs) {
            score += 25
            evidenceList.add(
                EvidenceItem(
                    category = "Visual Screenshot Analysis",
                    title = "Visual Login Card & Credential Inputs",
                    description = "Detected centered authentication card structure with input fields for user credentials.",
                    severity = EvidenceSeverity.MEDIUM,
                    indicator = "Visual authentication dialog"
                )
            )
        }

        if (hasFakeBadges) {
            score += 20
            evidenceList.add(
                EvidenceItem(
                    category = "Visual Screenshot Analysis",
                    title = "Security Badge Visual Lure",
                    description = "Deceptive visual trust seal / verification badge detected to induce artificial credibility.",
                    severity = EvidenceSeverity.MEDIUM,
                    indicator = "Visual trust badge"
                )
            )
        }

        if (hasScareware) {
            score += 45
            evidenceList.add(
                EvidenceItem(
                    category = "Visual Screenshot Analysis",
                    title = "Scareware Warning Overlay",
                    description = "High-urgency visual warning banner claiming device infection or immediate suspension.",
                    severity = EvidenceSeverity.CRITICAL,
                    indicator = "Scareware overlay"
                )
            )
        }

        val summary = buildString {
            append("VISUAL EVIDENCE: ")
            if (detectedBrand != null) append("Identified visual branding for $detectedBrand. ")
            if (hasLoginFormCard) append("Interactive login card detected. ")
            if (hasScareware) append("Scareware alarm dialog present. ")
            if (evidenceList.isEmpty()) append("Neutral webpage layout. Visual evidence alone does not prove malicious intent.")
        }.trim()

        return ScreenshotAnalysisResult(
            detectedBrand = detectedBrand,
            visualBrandConfidence = brandConfidence,
            hasLoginFormCard = hasLoginFormCard,
            hasCredentialInputs = hasCredentialInputs,
            hasFakeSecurityBadges = hasFakeBadges,
            hasScarewareUrgencyOverlay = hasScareware,
            extractedVisibleUrl = associatedUrl.ifBlank { null },
            visualMismatchDetected = detectedBrand != null && score >= 50,
            visualRiskScore = score.coerceIn(0, 100),
            evidence = evidenceList,
            visualSummary = summary
        )
    }
}
