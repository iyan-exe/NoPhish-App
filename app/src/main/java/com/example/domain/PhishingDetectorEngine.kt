package com.example.domain

import com.example.BuildConfig
import com.example.data.api.GeminiApiService
import com.example.data.api.GeminiContent
import com.example.data.api.GeminiGenerateRequest
import com.example.data.api.GeminiGenerationConfig
import com.example.data.api.GeminiPart
import com.example.data.api.RetrofitClient
import com.example.data.local.WhitelistDao
import com.example.data.model.AnalysisBreakdown
import com.example.data.model.EngineTelemetry
import com.example.data.model.PhishingAnalysisResult
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import kotlin.math.roundToInt

/**
 * Multi-Layered Phishing URL Detection Engine.
 *
 * Integrates:
 * 1. Supervised Machine Learning Classifier (UrlFeatureExtractor + SupervisedUrlClassifier)
 * 2. Retrieval-Augmented Language Model & Semantic Vector Space (RagThreatRetriever)
 * 3. NLP Semantic & Psychological Coercion Engine (NlpSemanticAnalyzer)
 * 4. Lexical, Syntactic, & Path Obfuscation Heuristics (UrlStructureAnalyzer)
 * 5. Brand Impersonation Radar & Levenshtein Distance (BrandImpersonationDetector)
 * 6. SQLite Room Database Whitelist & Threat Repository
 * 7. Gemini Neural Reasoning Engine
 */
class PhishingDetectorEngine(
    private val whitelistDao: WhitelistDao,
    private val geminiApiService: GeminiApiService = RetrofitClient.geminiService
) {
    private val moshi = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
    private val jsonAdapter = moshi.adapter(PhishingAnalysisResult::class.java)

    suspend fun analyze(url: String, contextText: String): PhishingAnalysisResult = withContext(Dispatchers.IO) {
        val trimmedUrl = url.trim()
        val trimmedContext = contextText.trim()

        // 1. Run local multi-layer analysis pipeline with REAL algorithms
        val urlAnalysis = UrlStructureAnalyzer.analyze(trimmedUrl)
        val mlResult = SupervisedUrlClassifier.predict(trimmedUrl)
        val ragQuery = "$trimmedUrl $trimmedContext ${urlAnalysis.cleanHost} ${urlAnalysis.path}"
        val ragResult = RagThreatRetriever.retrieve(ragQuery)
        val nlpAnalysis = NlpSemanticAnalyzer.analyze(trimmedContext)
        val brandCheck = BrandImpersonationDetector.evaluate(urlAnalysis.cleanHost, trimmedContext, trimmedUrl)
        val threatIntel = ThreatIntelligenceService.evaluate(urlAnalysis.cleanHost, urlAnalysis.path, trimmedUrl)

        // Whitelist DB check
        val whitelistEntity = whitelistDao.findByDomain(urlAnalysis.cleanHost)
            ?: whitelistDao.findByDomain(urlAnalysis.rootDomain)
            ?: if (urlAnalysis.cleanHost.contains(".")) {
                val root = DomainUtils.extractRootDomain(urlAnalysis.cleanHost)
                whitelistDao.findByDomain(root)
            } else null

        val isWhitelisted = whitelistEntity != null || urlAnalysis.isKnownLegitimate
        val verifiedBrandName = whitelistEntity?.brandName ?: if (urlAnalysis.isKnownLegitimate) "Verified Authority" else null
        val whitelistStatusStr = if (isWhitelisted) "Match Found ($verifiedBrandName)" else "No Match"

        // Build Engine Telemetry from genuine executed implementations
        val telemetry = EngineTelemetry(
            mlProbability = mlResult.probability,
            mlConfidence = mlResult.confidencePercentage,
            mlTopContributors = mlResult.topContributors.map { it.description },
            ragTopMatch = ragResult.matchedCampaignTitle,
            ragCosineSimilarity = ragResult.highestSimilarity,
            ragMatchedIocs = ragResult.topMatches.firstOrNull()?.matchedTerms ?: emptyList(),
            nlpUrgencyScore = nlpAnalysis.urgencyScore,
            nlpImperativeRatio = nlpAnalysis.imperativeRatio,
            nlpTactics = nlpAnalysis.pressureTactics,
            shannonEntropy = mlResult.features.vector[18],
            urlLength = trimmedUrl.length
        )

        // Baseline local synthesis
        val localResult = synthesizeLocalResult(
            url = trimmedUrl,
            contextText = trimmedContext,
            urlAnalysis = urlAnalysis,
            mlResult = mlResult,
            ragResult = ragResult,
            nlpAnalysis = nlpAnalysis,
            brandCheck = brandCheck,
            threatIntel = threatIntel,
            telemetry = telemetry,
            isWhitelisted = isWhitelisted,
            whitelistBrand = verifiedBrandName
        )

        // 2. Query Gemini API for neural reasoning if API key exists
        val apiKey = try {
            BuildConfig.GEMINI_API_KEY
        } catch (e: Throwable) {
            ""
        }

        if (apiKey.isNotBlank() && apiKey != "MY_GEMINI_API_KEY") {
            try {
                val prompt = buildGeminiPrompt(
                    url = trimmedUrl,
                    contextText = trimmedContext,
                    cleanHost = urlAnalysis.cleanHost,
                    isWhitelisted = isWhitelisted,
                    whitelistBrand = verifiedBrandName,
                    mlResult = mlResult,
                    ragResult = ragResult,
                    nlpAnalysis = nlpAnalysis,
                    localThreats = localResult.detectedThreats,
                    localScore = localResult.riskScore
                )

                val request = GeminiGenerateRequest(
                    contents = listOf(
                        GeminiContent(
                            parts = listOf(GeminiPart(text = prompt)),
                            role = "user"
                        )
                    ),
                    generationConfig = GeminiGenerationConfig(
                        responseMimeType = "application/json",
                        temperature = 0.1f
                    ),
                    systemInstruction = GeminiContent(
                        parts = listOf(
                            GeminiPart(
                                text = "You are an elite Cybersecurity Threat Intelligence & Phishing URL Classifier. Evaluate the target URL, RAG threat intelligence, and ML vector metrics. Distinguish between genuine established domains (Safe 0-10%) and actual phishing attempts (Phishing 70-100%). Respond ONLY in valid JSON conforming to the requested schema."
                            )
                        )
                    )
                )

                val response = try {
                    geminiApiService.generateContent(apiKey, request)
                } catch (e: Exception) {
                    geminiApiService.generateContentWithModel("gemini-2.5-flash", apiKey, request)
                }

                val rawText = response.candidates?.firstOrNull()?.content?.parts?.firstOrNull()?.text ?: ""

                if (rawText.isNotBlank()) {
                    val parsed = parseGeminiResponseSafely(
                        rawText = rawText,
                        fallback = localResult,
                        originalUrl = trimmedUrl,
                        originalContext = trimmedContext,
                        whitelistStatusStr = whitelistStatusStr,
                        telemetry = telemetry
                    )

                    if (parsed != null) {
                        val hasCriticalPathTampering = urlAnalysis.hasPathObfuscation ||
                                urlAnalysis.hasOpenRedirect ||
                                urlAnalysis.hasSuspiciousPayload ||
                                urlAnalysis.hasAtSymbolTrick ||
                                urlAnalysis.isIpAddress ||
                                urlAnalysis.isPunycode

                        val finalRiskScore = if ((isWhitelisted || urlAnalysis.isKnownLegitimate) && !brandCheck.isImpersonating && !hasCriticalPathTampering) {
                            minOf(parsed.riskScore, 10)
                        } else if (localResult.riskScore >= 65 && parsed.riskScore < 50) {
                            localResult.riskScore
                        } else {
                            maxOf(parsed.riskScore, localResult.riskScore)
                        }

                        val finalStatus = when {
                            finalRiskScore >= 65 -> "Phishing"
                            finalRiskScore >= 30 -> "Suspicious"
                            else -> "Safe"
                        }

                        val mergedThreats = if ((isWhitelisted || urlAnalysis.isKnownLegitimate) && !brandCheck.isImpersonating && !hasCriticalPathTampering) {
                            emptyList()
                        } else {
                            (parsed.detectedThreats + localResult.detectedThreats).distinct()
                        }

                        val finalResult = parsed.copy(
                            url = trimmedUrl,
                            status = finalStatus,
                            riskScore = finalRiskScore,
                            detectedThreats = mergedThreats,
                            engineTelemetry = telemetry,
                            contextText = trimmedContext,
                            scannedAt = System.currentTimeMillis()
                        )

                        val generatedJson = jsonAdapter.indent("  ").toJson(finalResult)
                        return@withContext finalResult.copy(rawJson = generatedJson)
                    }
                }
            } catch (e: Exception) {
                // If Gemini network call fails, seamlessly return mathematically rigorous local synthesis
            }
        }

        // Return local deterministic multi-layered scoring engine result
        return@withContext localResult
    }

    private fun synthesizeLocalResult(
        url: String,
        contextText: String,
        urlAnalysis: UrlStructureAnalysisResult,
        mlResult: MlInferenceResult,
        ragResult: RagRetrievalResult,
        nlpAnalysis: NlpAnalysisResult,
        brandCheck: BrandImpersonationResult,
        threatIntel: ThreatIntelResult,
        telemetry: EngineTelemetry,
        isWhitelisted: Boolean,
        whitelistBrand: String?
    ): PhishingAnalysisResult {
        val detectedThreats = mutableListOf<String>()

        var score = 0

        val hasCriticalPathTampering = urlAnalysis.hasPathObfuscation ||
                urlAnalysis.hasOpenRedirect ||
                urlAnalysis.hasSuspiciousPayload ||
                urlAnalysis.hasAtSymbolTrick ||
                urlAnalysis.isIpAddress ||
                urlAnalysis.isPunycode

        if ((isWhitelisted || urlAnalysis.isKnownLegitimate) && !brandCheck.isImpersonating && !hasCriticalPathTampering) {
            score = 0
        } else {
            detectedThreats.addAll(urlAnalysis.detectedThreats)
            detectedThreats.addAll(threatIntel.threatSignatures)

            if (ragResult.matchedCampaignTitle != null && ragResult.highestSimilarity >= 0.25f) {
                detectedThreats.add("RAG Vector Match: ${ragResult.matchedCampaignTitle} (${"%.1f".format(ragResult.highestSimilarity * 100)}% Cosine Sim)")
            }

            if (mlResult.isPhishing && mlResult.riskScore >= 60) {
                val primarySig = mlResult.topContributors.firstOrNull { it.isRiskIndication }?.description
                    ?: "Supervised ML classifier flagged high phishing probability (${"%.1f".format(mlResult.probability * 100)}%)"
                detectedThreats.add("ML Model Flag: $primarySig")
            }

            if (brandCheck.isImpersonating) {
                detectedThreats.add("Brand Impersonation (${brandCheck.impersonatedBrand ?: "Target"} vs untrusted domain '${urlAnalysis.cleanHost}')")
            }

            if (nlpAnalysis.hasUrgency) {
                detectedThreats.add("Psychological Coercion (${nlpAnalysis.pressureTactics.joinToString(", ")})")
            }

            // 1. Critical Base Factors
            if (brandCheck.isImpersonating) {
                score += if (brandCheck.mismatchSeverity == "Critical") 65 else 50
            }

            if (urlAnalysis.hasPathObfuscation) {
                score += 70 // Deceptive leetspeak substitution in URL path
            }

            if (urlAnalysis.hasOpenRedirect) {
                score += 65 // Open redirect vulnerability
            }

            if (urlAnalysis.hasSuspiciousPayload) {
                score += 75 // Direct malicious executable download
            }

            if (urlAnalysis.isIpAddress) {
                score += 55
            }

            if (urlAnalysis.typoSquattedBrand != null) {
                score += 55
            }

            if (urlAnalysis.hasAtSymbolTrick) {
                score += 45
            }

            if (urlAnalysis.isPunycode) {
                score += 40
            }

            // 2. High Threat Factors
            if (urlAnalysis.suspiciousTld != null) {
                score += 25
            }

            if (urlAnalysis.hasPhishingKeywords) {
                score += 30
            }

            if (urlAnalysis.isShortener) {
                score += 25
            }

            if (urlAnalysis.hasSuspiciousPort) {
                score += 20
            }

            if (urlAnalysis.excessiveSubdomains) {
                score += 20
            }

            if (urlAnalysis.hasHyphenStuffing) {
                score += 15
            }

            if (urlAnalysis.highEntropy) {
                score += 20
            }

            // 3. Supervised Machine Learning & RAG Fusion
            val mlRiskComponent = (mlResult.probability * 35.0f).roundToInt()
            score += mlRiskComponent

            if (ragResult.highestSimilarity >= 0.30f) {
                val ragComponent = (ragResult.highestSimilarity * 25.0f).roundToInt()
                score += ragComponent
            }

            // 4. NLP Urgency & Pretext Factors (Only on untrusted domains)
            if (nlpAnalysis.hasUrgency) {
                score += (nlpAnalysis.urgencyScore * 0.30).toInt()
            }
        }

        score = score.coerceIn(0, 100)

        // Status thresholds
        val status = when {
            score >= 65 -> "Phishing"
            score >= 30 -> "Suspicious"
            else -> "Safe"
        }

        val breakdown = AnalysisBreakdown(
            urlStructure = urlAnalysis.explanation,
            nlpUrgencyCheck = nlpAnalysis.explanation,
            brandImpersonation = brandCheck.explanation,
            whitelistStatus = if (isWhitelisted) "Match Found ($whitelistBrand)" else "No Match"
        )

        val userExplanation = generateUserFriendlyExplanation(
            status = status,
            score = score,
            brandCheck = brandCheck,
            urlAnalysis = urlAnalysis,
            mlResult = mlResult,
            ragResult = ragResult,
            nlpAnalysis = nlpAnalysis,
            isWhitelisted = isWhitelisted,
            whitelistBrand = whitelistBrand
        )

        val resultObj = PhishingAnalysisResult(
            url = url,
            status = status,
            riskScore = score,
            detectedThreats = detectedThreats.distinct(),
            analysisBreakdown = breakdown,
            userExplanation = userExplanation,
            engineTelemetry = telemetry,
            scannedAt = System.currentTimeMillis(),
            contextText = contextText
        )

        val generatedJson = jsonAdapter.indent("  ").toJson(resultObj)

        return resultObj.copy(rawJson = generatedJson)
    }

    private fun parseGeminiResponseSafely(
        rawText: String,
        fallback: PhishingAnalysisResult,
        originalUrl: String,
        originalContext: String,
        whitelistStatusStr: String,
        telemetry: EngineTelemetry
    ): PhishingAnalysisResult? {
        try {
            val cleanJson = cleanJsonOutput(rawText)
            val root = JSONObject(cleanJson)

            val scoreRaw = root.opt("risk_score") ?: root.opt("riskScore") ?: root.opt("score") ?: fallback.riskScore
            val score = when (scoreRaw) {
                is Number -> scoreRaw.toInt()
                is String -> scoreRaw.trim().toIntOrNull() ?: fallback.riskScore
                else -> fallback.riskScore
            }.coerceIn(0, 100)

            val statusRaw = root.optString("status", "").ifBlank {
                root.optString("verdict", "").ifBlank {
                    when {
                        score >= 65 -> "Phishing"
                        score >= 30 -> "Suspicious"
                        else -> "Safe"
                    }
                }
            }

            val status = when {
                statusRaw.contains("phish", ignoreCase = true) -> "Phishing"
                statusRaw.contains("susp", ignoreCase = true) -> "Suspicious"
                else -> "Safe"
            }

            val threatsList = mutableListOf<String>()
            val threatsArray = root.optJSONArray("detected_threats") ?: root.optJSONArray("detectedThreats")
            if (threatsArray != null) {
                for (i in 0 until threatsArray.length()) {
                    val item = threatsArray.optString(i)
                    if (item.isNotBlank()) threatsList.add(item)
                }
            } else {
                threatsList.addAll(fallback.detectedThreats)
            }

            val breakdownObj = root.optJSONObject("analysis_breakdown") ?: root.optJSONObject("analysisBreakdown")
            val urlStructure = breakdownObj?.optString("url_structure") 
                ?: breakdownObj?.optString("urlStructure") 
                ?: fallback.analysisBreakdown.urlStructure

            val nlpCheck = breakdownObj?.optString("nlp_urgency_check") 
                ?: breakdownObj?.optString("nlpUrgencyCheck") 
                ?: fallback.analysisBreakdown.nlpUrgencyCheck

            val brandImpersonation = breakdownObj?.optString("brand_impersonation") 
                ?: breakdownObj?.optString("brandImpersonation") 
                ?: fallback.analysisBreakdown.brandImpersonation

            val userExplanation = root.optString("user_explanation").ifBlank {
                root.optString("userExplanation").ifBlank {
                    root.optString("explanation").ifBlank {
                        fallback.userExplanation
                    }
                }
            }

            return PhishingAnalysisResult(
                url = originalUrl,
                status = status,
                riskScore = score,
                detectedThreats = threatsList.distinct(),
                analysisBreakdown = AnalysisBreakdown(
                    urlStructure = urlStructure,
                    nlpUrgencyCheck = nlpCheck,
                    brandImpersonation = brandImpersonation,
                    whitelistStatus = whitelistStatusStr
                ),
                userExplanation = userExplanation,
                engineTelemetry = telemetry,
                rawJson = cleanJson,
                scannedAt = System.currentTimeMillis(),
                contextText = originalContext
            )
        } catch (e: Exception) {
            return null
        }
    }

    private fun generateUserFriendlyExplanation(
        status: String,
        score: Int,
        brandCheck: BrandImpersonationResult,
        urlAnalysis: UrlStructureAnalysisResult,
        mlResult: MlInferenceResult,
        ragResult: RagRetrievalResult,
        nlpAnalysis: NlpAnalysisResult,
        isWhitelisted: Boolean,
        whitelistBrand: String?
    ): String {
        return buildString {
            when (status) {
                "Phishing" -> {
                    append("DANGER: High-risk PHISHING threat detected (Risk Score: $score/100, ML Probability: ${(mlResult.probability * 100).toInt()}%). ")
                    if (urlAnalysis.hasPathObfuscation) {
                        append("CRITICAL PATH DECEPTION: The URL path employs deceptive leetspeak/character substitution ('l0gin' spoofing 'login'). Legitimate services NEVER use digit-substituted endpoint paths. ")
                    }
                    if (urlAnalysis.hasOpenRedirect) {
                        append("OPEN REDIRECT RISK: The URL contains an open redirect parameter pointing traffic to an external target. ")
                    }
                    if (urlAnalysis.hasSuspiciousPayload) {
                        append("DANGEROUS PAYLOAD: The URL targets a direct application or executable installer (.apk / .exe). ")
                    }
                    if (brandCheck.isImpersonating) {
                        append("This site is actively impersonating ${brandCheck.impersonatedBrand}, while leading to an unauthorized domain ('${urlAnalysis.cleanHost}') instead of official portal ('${brandCheck.legitimateDomain}'). ")
                    }
                    if (ragResult.matchedCampaignTitle != null && ragResult.highestSimilarity >= 0.25f) {
                        append("Threat matched intelligence profile '${ragResult.matchedCampaignTitle}' (${(ragResult.highestSimilarity * 100).toInt()}% cosine similarity). ")
                    }
                    if (urlAnalysis.isIpAddress) {
                        append("The URL uses a raw numerical IP address (${urlAnalysis.cleanHost}) commonly used to evade domain reputation filters. ")
                    }
                    if (urlAnalysis.suspiciousTld != null) {
                        append("The domain utilizes an untrusted Top-Level Domain (.${urlAnalysis.suspiciousTld}) heavily associated with scam operations. ")
                    }
                    if (nlpAnalysis.hasUrgency) {
                        append("The accompanying message employs artificial urgency and coercion tactics. ")
                    }
                    append("Do NOT visit this link, enter credentials, or make payments.")
                }
                "Suspicious" -> {
                    append("WARNING: This URL exhibits risk indicators (Risk Score: $score/100). ")
                    if (urlAnalysis.hasPathObfuscation) {
                        append("Deceptive character substitution / leetspeak detected in URL path. ")
                    } else if (urlAnalysis.hasOpenRedirect) {
                        append("Open redirect destination detected in URL query. ")
                    } else if (urlAnalysis.detectedThreats.isNotEmpty()) {
                        append("Issues identified: ${urlAnalysis.detectedThreats.first()}. ")
                    }
                    if (nlpAnalysis.hasUrgency) {
                        append("The message employs urgency tactics. ")
                    }
                    append("Exercise caution and verify directly through the official provider before opening.")
                }
                else -> {
                    if (isWhitelisted) {
                        append("SAFE: The domain '${urlAnalysis.cleanHost}' is verified as an official entity (${whitelistBrand ?: "Verified Authority"}). Standard cybersecurity checks found no deceptive manipulation.")
                    } else {
                        append("SAFE: Multi-layer cybersecurity analysis (ML probability ${(mlResult.probability * 100).toInt()}%, 0 RAG threats) found no deceptive patterns, brand mismatches, or malicious signatures for '${urlAnalysis.cleanHost}'.")
                    }
                }
            }
        }
    }

    private fun buildGeminiPrompt(
        url: String,
        contextText: String,
        cleanHost: String,
        isWhitelisted: Boolean,
        whitelistBrand: String?,
        mlResult: MlInferenceResult,
        ragResult: RagRetrievalResult,
        nlpAnalysis: NlpAnalysisResult,
        localThreats: List<String>,
        localScore: Int
    ): String {
        return """
Evaluate the following URL and message context for phishing, scam, and brand impersonation threats:

URL: $url
Context/Text: $contextText
Extracted Host Domain: $cleanHost
SQL Whitelist Match: ${if (isWhitelisted) "Match Found ($whitelistBrand)" else "No Match"}

EXECUTED MACHINE LEARNING INFERENCE:
- Model: Supervised Logistic Regression Classifier (24 features, L2 regularized)
- Inferred Probability P(Phishing): ${"%.4f".format(mlResult.probability)} (${"%.1f".format(mlResult.probability * 100)}%)
- Confidence Level: ${"%.1f".format(mlResult.confidencePercentage)}%
- Top ML Contributing Features:
${mlResult.topContributors.take(4).joinToString("\n") { "  * ${it.description}" }}

RETRIEVAL-AUGMENTED INTELLIGENCE (RAG):
${ragResult.ragContextForPrompt}

NLP SEMANTIC & PSYCHOLOGICAL COERCION ANALYSIS:
- Urgency Pressure Score: ${nlpAnalysis.urgencyScore} / 100
- Imperative Command Ratio: ${"%.1f".format(nlpAnalysis.imperativeRatio * 100)}%
- Detected Tactics: ${if (nlpAnalysis.pressureTactics.isEmpty()) "None" else nlpAnalysis.pressureTactics.joinToString("; ")}

Preliminary Local Threat Signals: ${if (localThreats.isEmpty()) "None" else localThreats.joinToString("; ")}
Composite Pre-Score: $localScore / 100

ANALYSIS GUIDELINES:
- Official websites with standard paths (e.g. sbi.bank.in, onlinesbi.sbi/retail/login, hdfcbank.com, google.com) are SAFE (Risk Score: 0-10).
- CRITICAL PATH ANOMALY: If a URL on ANY domain (even official/whitelisted ones) contains leetspeak/character substitution in the path (e.g. /l0gin with zero, /s1gnin with one, /ver1fy, /p4ssword), or open redirect parameters (e.g. ?url=http://...), this is DECEPTIVE/SPOOFED. Classify as PHISHING or SUSPICIOUS (Risk Score: 70-100).
- If an untrusted third-party host attempts to impersonate a bank or brand (e.g. sbi-kyc-update.xyz, hdfc-netbanking.club, inddiapost.top, secure-appleid.com, 192.168.1.1/chase), it is PHISHING (Risk Score: 75-100).
- If the domain is officially verified and has NO path tampering, status is "Safe" (risk_score 0-10).

Return the analysis STRICTLY as JSON with these exact keys:
{
  "url": "$url",
  "status": "Safe | Suspicious | Phishing",
  "risk_score": <Integer 0-100>,
  "detected_threats": [
    "<Specific Threat 1>",
    "<Specific Threat 2>"
  ],
  "analysis_breakdown": {
    "url_structure": "<Detailed domain/path analysis>",
    "nlp_urgency_check": "<Scam language & urgency analysis>",
    "brand_impersonation": "<Brand vs domain mismatch analysis>",
    "whitelist_status": "${if (isWhitelisted) "Match Found ($whitelistBrand)" else "No Match"}"
  },
  "user_explanation": "<A clear, non-technical explanation for the user explaining why this URL received this classification.>"
}
""".trimIndent()
    }

    private fun cleanJsonOutput(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.startsWith("```json") && trimmed.endsWith("```")) {
            return trimmed.removePrefix("```json").removeSuffix("```").trim()
        }
        if (trimmed.startsWith("```") && trimmed.endsWith("```")) {
            return trimmed.removePrefix("```").removeSuffix("```").trim()
        }
        val firstBrace = trimmed.indexOf('{')
        val lastBrace = trimmed.lastIndexOf('}')
        if (firstBrace != -1 && lastBrace != -1 && lastBrace > firstBrace) {
            return trimmed.substring(firstBrace, lastBrace + 1)
        }
        return trimmed
    }
}
