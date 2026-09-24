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
import com.example.data.model.EvidenceItem
import com.example.data.model.EvidenceSeverity
import com.example.data.model.PhishingAnalysisResult
import com.example.data.model.ScanStatus
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import kotlin.math.roundToInt

/**
 * Multi-Layered Phishing Detection Platform Engine (NoPhish 2.0).
 *
 * Integrates:
 * 1. Supervised Machine Learning Classifier (UrlFeatureExtractor + SupervisedUrlClassifier)
 * 2. Retrieval-Augmented Language Model & Semantic Vector Space (RagThreatRetriever)
 * 3. NLP Semantic & Psychological Coercion Engine (NlpSemanticAnalyzer)
 * 4. Lexical, Syntactic, & Path Obfuscation Heuristics (UrlStructureAnalyzer)
 * 5. Brand Impersonation Radar & Levenshtein Distance (BrandImpersonationDetector)
 * 6. SQLite Room Database Whitelist & Threat Repository
 * 7. HTML & Credential Harvesting Page Analyzer (HtmlWebpageAnalyzer)
 * 8. Redirect Chain Inspector & Shortener Cloaking (RedirectChainAnalyzer)
 * 9. QR / Quishing Code Analysis (QrCodeAnalyzer)
 * 10. Screenshot Visual Evidence Analyzer (ScreenshotAnalyzer)
 * 11. Gemini Neural Reasoning Engine
 */
class PhishingDetectorEngine(
    private val whitelistDao: WhitelistDao,
    private val geminiApiService: GeminiApiService = RetrofitClient.geminiService
) {
    private val moshi = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
    private val jsonAdapter = moshi.adapter(PhishingAnalysisResult::class.java)

    suspend fun analyze(
        url: String,
        contextText: String,
        htmlContent: String = "",
        redirectUrls: List<String> = emptyList(),
        qrPayload: String? = null,
        screenshotText: String? = null,
        isBlockedDomain: Boolean = false
    ): PhishingAnalysisResult = withContext(Dispatchers.IO) {
        val trimmedUrl = url.trim()
        val trimmedContext = contextText.trim()

        // 1. Run local multi-layer analysis pipeline with REAL algorithms
        val urlAnalysis = UrlStructureAnalyzer.analyze(trimmedUrl)
        val mlResult = SupervisedUrlClassifier.predict(trimmedUrl)

        // Sensitive tokens/session parameters should NEVER be sent to external AI/RAG services
        val sanitizedQuery = PathAnomalyDetector.redactSensitiveQueryParams(urlAnalysis.query)
        val sanitizedUrlForAi = if (sanitizedQuery.isNotBlank() && urlAnalysis.query.isNotBlank()) {
            val baseBeforeQuery = trimmedUrl.substringBefore('?')
            "$baseBeforeQuery?$sanitizedQuery"
        } else {
            trimmedUrl
        }

        val ragQuery = "$sanitizedUrlForAi $trimmedContext ${urlAnalysis.cleanHost} ${urlAnalysis.path} ${if (urlAnalysis.hasPathLookalike) "lookalike path typo" else ""}"
        val ragResult = RagThreatRetriever.retrieve(ragQuery)
        val nlpAnalysis = NlpSemanticAnalyzer.analyze(trimmedContext)
        val brandCheck = BrandImpersonationDetector.evaluate(urlAnalysis.cleanHost, trimmedContext, trimmedUrl)
        val threatIntel = ThreatIntelligenceService.evaluate(urlAnalysis.cleanHost, urlAnalysis.path, trimmedUrl)

        // Multimodal Modules
        val htmlAnalysis = HtmlWebpageAnalyzer.analyze(htmlContent, trimmedUrl)
        val redirectAnalysis = if (redirectUrls.isNotEmpty()) {
            RedirectChainAnalyzer.analyzeChain(redirectUrls)
        } else {
            RedirectChainAnalyzer.analyzeChain(listOf(trimmedUrl))
        }
        val qrAnalysis = if (!qrPayload.isNullOrBlank()) {
            QrCodeAnalyzer.extractAndEvaluate(qrPayload)
        } else null
        val screenshotAnalysis = if (!screenshotText.isNullOrBlank()) {
            ScreenshotAnalyzer.analyzeScreenshot(null, trimmedUrl, screenshotText)
        } else null

        // Whitelist DB check: A legitimate parent domain must NEVER confer whitelist immunity
        // to an unauthorized typosquatted or lookalike subdomain!
        val rawWhitelistEntity = whitelistDao.findByDomain(urlAnalysis.cleanHost)
            ?: if (!urlAnalysis.hasSubdomainLookalike) {
                whitelistDao.findByDomain(urlAnalysis.rootDomain)
                    ?: if (urlAnalysis.cleanHost.contains(".")) {
                        val root = DomainUtils.extractRootDomain(urlAnalysis.cleanHost)
                        whitelistDao.findByDomain(root)
                    } else null
            } else null

        val isWhitelisted = if (urlAnalysis.hasSubdomainLookalike) {
            false
        } else {
            rawWhitelistEntity != null || urlAnalysis.isKnownLegitimate
        }

        val verifiedBrandName = rawWhitelistEntity?.brandName ?: if (urlAnalysis.isKnownLegitimate && !urlAnalysis.hasSubdomainLookalike) "Verified Authority" else null
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
            urlLength = trimmedUrl.length,
            inputType = when {
                qrAnalysis != null -> "QR_CODE"
                screenshotAnalysis != null -> "SCREENSHOT"
                htmlContent.isNotBlank() -> "HTML_PAGE"
                else -> "URL"
            },
            modelVersion = "v2.0.0-multimodal"
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
            htmlAnalysis = htmlAnalysis,
            redirectAnalysis = redirectAnalysis,
            qrAnalysis = qrAnalysis,
            screenshotAnalysis = screenshotAnalysis,
            telemetry = telemetry,
            isWhitelisted = isWhitelisted,
            whitelistBrand = verifiedBrandName,
            isBlockedDomain = isBlockedDomain
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
                    urlAnalysis = urlAnalysis,
                    brandCheck = brandCheck,
                    threatIntel = threatIntel,
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
                                text = "You are an elite Cybersecurity Threat Intelligence & Phishing URL Classifier for NoPhish 2.0. Strictly evaluate the target URL, RAG threat intelligence, NLP urgency metrics, and ML vector features using ONLY the supplied technical evidence. Never claim a site is absolutely safe simply because no threat was detected. If evidence is insufficient, say so. Local deterministic threat detections (brand impersonation, path leetspeak tampering, open redirects, executable downloads, external forms) represent ground truth and must never be downgraded. Respond ONLY in valid JSON matching the requested schema."
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
                                urlAnalysis.isPunycode ||
                                urlAnalysis.hasSubdomainLookalike ||
                                (urlAnalysis.hasPathAnomaly && urlAnalysis.pathAnomalyScore >= 60) ||
                                htmlAnalysis.hasExternalFormAction

                        val isDeterministicThreat = brandCheck.isImpersonating ||
                                hasCriticalPathTampering ||
                                (urlAnalysis.hasSubdomainLookalike && (urlAnalysis.hasPathLookalike || urlAnalysis.hasPathAnomaly || urlAnalysis.hasLoginContext)) ||
                                (mlResult.isPhishing && mlResult.probability >= 0.85f) ||
                                threatIntel.reputationScore <= 20 ||
                                (ragResult.highestSimilarity >= 0.35f && ragResult.topMatches.firstOrNull()?.document?.severity == "CRITICAL")

                        val finalRiskScore = when {
                            // 1. Whitelisted domain with path tampering, subdomain lookalike, or brand spoofing is NEVER safe
                            hasCriticalPathTampering || brandCheck.isImpersonating || (urlAnalysis.hasSubdomainLookalike && (urlAnalysis.hasPathLookalike || urlAnalysis.hasPathAnomaly || urlAnalysis.hasLoginContext)) -> {
                                maxOf(parsed.riskScore, localResult.riskScore, 75)
                            }
                            // 2. Verified legitimate / whitelisted domain with clean path
                            (isWhitelisted || urlAnalysis.isKnownLegitimate) && !isDeterministicThreat && !urlAnalysis.hasPathLookalike && !urlAnalysis.hasPathAnomaly -> {
                                minOf(parsed.riskScore, 10)
                            }
                            // 3. Verified legitimate / whitelisted domain with lookalike path manipulation:
                            (isWhitelisted || urlAnalysis.isKnownLegitimate) && (urlAnalysis.hasPathLookalike || urlAnalysis.hasPathAnomaly) -> {
                                if (parsed.riskScore >= 65) 40 else maxOf(parsed.riskScore, 35)
                            }
                            // 4. Local engine detected a deterministic threat
                            isDeterministicThreat -> {
                                maxOf(parsed.riskScore, localResult.riskScore, 65)
                            }
                            // 5. Standard fusion
                            else -> {
                                maxOf(parsed.riskScore, localResult.riskScore)
                            }
                        }

                        val finalStatus = when {
                            isBlockedDomain -> "BLOCKED"
                            finalRiskScore >= 76 -> "LIKELY PHISHING"
                            finalRiskScore >= 51 -> "HIGH RISK"
                            finalRiskScore >= 21 -> "SUSPICIOUS"
                            else -> "LOW RISK"
                        }

                        val mergedThreats = if ((isWhitelisted || urlAnalysis.isKnownLegitimate) && !brandCheck.isImpersonating && !hasCriticalPathTampering && !urlAnalysis.hasPathLookalike && !urlAnalysis.hasPathAnomaly) {
                            emptyList()
                        } else {
                            (parsed.detectedThreats + localResult.detectedThreats).distinct()
                        }

                        val userExplanationWithOverride = if (isDeterministicThreat && parsed.riskScore < 50) {
                            "${parsed.userExplanation} [Deterministic Security Override Enforced: Verified local threat indicators (e.g. brand spoofing, path tampering, or ML signature) took precedence over model reasoning.]"
                        } else {
                            parsed.userExplanation
                        }

                        val finalResult = parsed.copy(
                            url = trimmedUrl,
                            status = finalStatus,
                            riskScore = finalRiskScore,
                            detectedThreats = mergedThreats,
                            userExplanation = userExplanationWithOverride,
                            recommendation = localResult.recommendation,
                            evidenceList = localResult.evidenceList,
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
        htmlAnalysis: HtmlAnalysisResult,
        redirectAnalysis: RedirectChainResult,
        qrAnalysis: QrAnalysisResult?,
        screenshotAnalysis: ScreenshotAnalysisResult?,
        telemetry: EngineTelemetry,
        isWhitelisted: Boolean,
        whitelistBrand: String?,
        isBlockedDomain: Boolean = false
    ): PhishingAnalysisResult {
        val detectedThreats = mutableListOf<String>()
        val evidenceList = mutableListOf<EvidenceItem>()

        var score = 0

        val hasCriticalPathTampering = urlAnalysis.hasPathObfuscation ||
                urlAnalysis.hasOpenRedirect ||
                urlAnalysis.hasSuspiciousPayload ||
                urlAnalysis.hasAtSymbolTrick ||
                urlAnalysis.isIpAddress ||
                urlAnalysis.isPunycode ||
                urlAnalysis.hasSubdomainLookalike

        if ((isWhitelisted || urlAnalysis.isKnownLegitimate) && !brandCheck.isImpersonating && !hasCriticalPathTampering && !urlAnalysis.hasPathLookalike && !urlAnalysis.hasPathAnomaly) {
            score = 0
            evidenceList.add(
                EvidenceItem(
                    category = "Domain Legitimacy",
                    title = "Verified Legitimate Domain Authority",
                    description = "The root domain '${urlAnalysis.cleanHost}' is recognized as an official entity (${whitelistBrand ?: "Verified Authority"}).",
                    severity = EvidenceSeverity.LOW,
                    indicator = "Official Authority"
                )
            )
        } else if ((isWhitelisted || urlAnalysis.isKnownLegitimate) && !brandCheck.isImpersonating && !hasCriticalPathTampering && (urlAnalysis.hasPathLookalike || urlAnalysis.hasPathAnomaly)) {
            detectedThreats.addAll(urlAnalysis.detectedThreats)
            score = 35
            evidenceList.add(
                EvidenceItem(
                    category = "Path Structure",
                    title = "Lookalike Path on Legitimate Host",
                    description = "Path segment contains transposition or character manipulation imitating official routes.",
                    severity = EvidenceSeverity.MEDIUM,
                    indicator = urlAnalysis.path
                )
            )
        } else {
            detectedThreats.addAll(urlAnalysis.detectedThreats)
            detectedThreats.addAll(threatIntel.threatSignatures)

            if (ragResult.matchedCampaignTitle != null && ragResult.highestSimilarity >= 0.25f) {
                detectedThreats.add("RAG Vector Match: ${ragResult.matchedCampaignTitle} (${"%.1f".format(ragResult.highestSimilarity * 100)}% Cosine Sim)")
                evidenceList.add(
                    EvidenceItem(
                        category = "Threat Intelligence",
                        title = "Known Phishing Campaign Match",
                        description = "Pattern matched profile '${ragResult.matchedCampaignTitle}' in threat intelligence vector repository.",
                        severity = EvidenceSeverity.HIGH,
                        indicator = "${"%.1f".format(ragResult.highestSimilarity * 100)}% similarity"
                    )
                )
            } else {
                evidenceList.add(
                    EvidenceItem(
                        category = "Threat Intelligence",
                        title = "Threat Intelligence Lookup",
                        description = "No matching threat intelligence found in local signatures. (Absence of data is not proof of safety).",
                        severity = EvidenceSeverity.NEUTRAL,
                        indicator = "No Match Found"
                    )
                )
            }

            if (mlResult.isPhishing && mlResult.riskScore >= 60) {
                val primarySig = mlResult.topContributors.firstOrNull { it.isRiskIndication }?.description
                    ?: "Supervised ML classifier flagged high phishing probability (${"%.1f".format(mlResult.probability * 100)}%)"
                detectedThreats.add("ML Model Flag: $primarySig")
                evidenceList.add(
                    EvidenceItem(
                        category = "Machine Learning",
                        title = "Supervised Classifier Prediction",
                        description = "L2-regularized logistic regression model computed high phishing probability (${"%.1f".format(mlResult.probability * 100)}%).",
                        severity = EvidenceSeverity.HIGH,
                        indicator = primarySig
                    )
                )
            }

            if (brandCheck.isImpersonating) {
                val threatDesc = "Brand Impersonation (${brandCheck.impersonatedBrand ?: "Target"} vs untrusted domain '${urlAnalysis.cleanHost}')"
                detectedThreats.add(threatDesc)
                evidenceList.add(
                    EvidenceItem(
                        category = "Brand Analysis",
                        title = "Target Brand Spoofing",
                        description = "Site targets visual/textual brand '${brandCheck.impersonatedBrand}' on untrusted domain '${urlAnalysis.cleanHost}'.",
                        severity = EvidenceSeverity.CRITICAL,
                        indicator = brandCheck.impersonatedBrand ?: "Spoofed Brand"
                    )
                )
            }

            if (nlpAnalysis.hasUrgency) {
                detectedThreats.add("Psychological Coercion (${nlpAnalysis.pressureTactics.joinToString(", ")})")
                evidenceList.add(
                    EvidenceItem(
                        category = "NLP Psychological Analysis",
                        title = "Artificial Urgency & Coercion",
                        description = "Context message employs coercive pressure tactics: ${nlpAnalysis.pressureTactics.joinToString(", ")}.",
                        severity = EvidenceSeverity.MEDIUM,
                        indicator = "Urgency Score: ${nlpAnalysis.urgencyScore}/100"
                    )
                )
            }

            // 1. Critical Base Factors
            if (brandCheck.isImpersonating) {
                score += if (brandCheck.mismatchSeverity == "Critical") 65 else 50
            }

            if (urlAnalysis.hasSubdomainLookalike) {
                score += 65
                evidenceList.add(
                    EvidenceItem(
                        category = "Subdomain Analysis",
                        title = "Deceptive Lookalike Subdomain",
                        description = "Subdomain spoofs an authoritative institution to mislead mobile address-bar truncation.",
                        severity = EvidenceSeverity.CRITICAL,
                        indicator = urlAnalysis.subdomainLookalikeMatch?.candidate ?: "Subdomain Spoof"
                    )
                )
            }

            if (urlAnalysis.hasSubdomainLookalike && (urlAnalysis.hasPathLookalike || urlAnalysis.hasPathAnomaly || urlAnalysis.hasLoginContext)) {
                score += 25
            }

            if (urlAnalysis.hasPathObfuscation) {
                score += 70
                evidenceList.add(
                    EvidenceItem(
                        category = "Path Structure",
                        title = "Leetspeak Character Substitution",
                        description = "Endpoint path uses digit substitution (e.g. 'l0gin') to evade keyword blockers.",
                        severity = EvidenceSeverity.CRITICAL,
                        indicator = "Leetspeak in path"
                    )
                )
            }

            if (urlAnalysis.hasPathAnomaly) {
                score += maxOf(urlAnalysis.pathAnomalyScore, 48)
            } else if (urlAnalysis.hasPathLookalike) {
                score += 45
            }

            if (urlAnalysis.hasOpenRedirect) {
                score += 65
                evidenceList.add(
                    EvidenceItem(
                        category = "Redirect Analysis",
                        title = "Open Redirect Parameter",
                        description = "URL contains an unvalidated redirect parameter pointing traffic to an external target.",
                        severity = EvidenceSeverity.HIGH,
                        indicator = "Open redirect detected"
                    )
                )
            }

            if (urlAnalysis.hasSuspiciousPayload) {
                score += 75
                evidenceList.add(
                    EvidenceItem(
                        category = "Payload Analysis",
                        title = "Malicious Executable Download Link",
                        description = "URL links directly to executable or application package installer (.apk / .exe).",
                        severity = EvidenceSeverity.CRITICAL,
                        indicator = "Direct binary payload"
                    )
                )
            }

            if (urlAnalysis.isIpAddress) {
                score += 55
                evidenceList.add(
                    EvidenceItem(
                        category = "Host Analysis",
                        title = "Raw IP Address Host",
                        description = "URL uses raw dotted-decimal IP address (${urlAnalysis.cleanHost}) bypassing standard DNS registries.",
                        severity = EvidenceSeverity.HIGH,
                        indicator = urlAnalysis.cleanHost
                    )
                )
            }

            if (urlAnalysis.typoSquattedBrand != null) {
                score += 55
                evidenceList.add(
                    EvidenceItem(
                        category = "Domain Typosquatting",
                        title = "Typosquatted Brand Collision",
                        description = "Domain '${urlAnalysis.cleanHost}' is a close visual misspelling of legitimate brand '${urlAnalysis.typoSquattedBrand}'.",
                        severity = EvidenceSeverity.CRITICAL,
                        indicator = urlAnalysis.typoSquattedBrand ?: ""
                    )
                )
            }

            if (urlAnalysis.hasAtSymbolTrick) {
                score += 45
            }

            if (urlAnalysis.isPunycode) {
                score += 40
                evidenceList.add(
                    EvidenceItem(
                        category = "Unicode / Homoglyph",
                        title = "Punycode IDN Homoglyph",
                        description = "Domain uses internationalized characters to mimic standard Latin characters visually.",
                        severity = EvidenceSeverity.HIGH,
                        indicator = urlAnalysis.cleanHost
                    )
                )
            }

            // 2. High Threat Factors
            if (urlAnalysis.suspiciousTld != null) {
                score += 25
                evidenceList.add(
                    EvidenceItem(
                        category = "TLD Analysis",
                        title = "High-Risk Top-Level Domain",
                        description = "Domain utilizes .${urlAnalysis.suspiciousTld} which has disproportionately high spam/abuse rates.",
                        severity = EvidenceSeverity.MEDIUM,
                        indicator = ".${urlAnalysis.suspiciousTld}"
                    )
                )
            }

            if (urlAnalysis.hasPhishingKeywords) {
                score += 30
            }

            if (urlAnalysis.isShortener) {
                score += 25
                evidenceList.add(
                    EvidenceItem(
                        category = "URL Cloaking",
                        title = "URL Shortener Detected",
                        description = "Shortened URL masks final destination domain and certificate details.",
                        severity = EvidenceSeverity.MEDIUM,
                        indicator = urlAnalysis.cleanHost
                    )
                )
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
                evidenceList.add(
                    EvidenceItem(
                        category = "Lexical Entropy",
                        title = "High Shannon Entropy",
                        description = "Hostname exhibits high randomness characteristic of algorithmically generated domains (DGA).",
                        severity = EvidenceSeverity.MEDIUM,
                        indicator = "Entropy: ${"%.2f".format(telemetry.shannonEntropy)}"
                    )
                )
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

            // 5. Multimodal HTML & Redirect signals
            if (htmlAnalysis.hasExternalFormAction) {
                score += 50
                detectedThreats.add("HTML Credential Siphon: Form posts to external domain")
                evidenceList.addAll(htmlAnalysis.evidence)
            } else if (htmlAnalysis.hasLoginForm) {
                score += 15
                evidenceList.addAll(htmlAnalysis.evidence)
            }

            if (redirectAnalysis.hasExcessiveRedirects || redirectAnalysis.hasOpenRedirectParam) {
                score += redirectAnalysis.redirectRiskScore
                evidenceList.addAll(redirectAnalysis.evidence)
            }

            if (qrAnalysis != null && qrAnalysis.qrRiskScore > 0) {
                score += qrAnalysis.qrRiskScore
                evidenceList.addAll(qrAnalysis.evidence)
            }

            if (screenshotAnalysis != null && screenshotAnalysis.visualRiskScore > 0) {
                score += screenshotAnalysis.visualRiskScore
                evidenceList.addAll(screenshotAnalysis.evidence)
            }
        }

        if (isBlockedDomain) {
            score = 100
        }

        score = score.coerceIn(0, 100)

        // Status thresholds complying strictly with NoPhish 2.0 terminology
        val status = when {
            isBlockedDomain -> "BLOCKED"
            score >= 76 -> "LIKELY PHISHING"
            score >= 51 -> "HIGH RISK"
            score >= 21 -> "SUSPICIOUS"
            else -> "LOW RISK"
        }

        val recommendation = when {
            isBlockedDomain -> "CRITICAL: BLOCKED DOMAIN. This domain is confirmed malicious. Immediate block enforced. Do not open."
            score >= 76 -> "CRITICAL: LIKELY PHISHING. Do NOT enter passwords, OTPs, or payment details. If received via email/SMS, report immediately."
            score >= 51 -> "HIGH RISK: Suspicious deceptive indicators detected. Do not submit sensitive forms. Verify identity through official external channels."
            score >= 21 -> "SUSPICIOUS: Moderate anomaly patterns detected. Exercise caution and verify URL spelling before proceeding."
            else -> "LOW RISK: No overt phishing signatures detected. Absence of detected threats does not guarantee absolute safety. Always practice standard cybersecurity hygiene."
        }

        val breakdown = AnalysisBreakdown(
            urlStructure = urlAnalysis.explanation,
            nlpUrgencyCheck = nlpAnalysis.explanation,
            brandImpersonation = brandCheck.explanation,
            whitelistStatus = if (isWhitelisted) "Match Found ($whitelistBrand)" else "No Match",
            htmlAnalysis = htmlAnalysis.summary,
            redirectChain = redirectAnalysis.summary,
            visualAnalysis = screenshotAnalysis?.visualSummary ?: "No screenshot analyzed"
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
            recommendation = recommendation,
            evidenceList = evidenceList.distinctBy { it.title },
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
                        score >= 76 -> "LIKELY PHISHING"
                        score >= 51 -> "HIGH RISK"
                        score >= 21 -> "SUSPICIOUS"
                        else -> "LOW RISK"
                    }
                }
            }

            val status = when {
                statusRaw.contains("BLOCK", ignoreCase = true) -> "BLOCKED"
                statusRaw.contains("LIKELY", ignoreCase = true) || (statusRaw.contains("PHISH", ignoreCase = true) && !statusRaw.contains("LOW", ignoreCase = true)) -> "LIKELY PHISHING"
                statusRaw.contains("HIGH", ignoreCase = true) -> "HIGH RISK"
                statusRaw.contains("SUSP", ignoreCase = true) -> "SUSPICIOUS"
                else -> "LOW RISK"
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

            val recommendation = root.optString("recommendation").ifBlank {
                fallback.recommendation
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
                    whitelistStatus = whitelistStatusStr,
                    htmlAnalysis = fallback.analysisBreakdown.htmlAnalysis,
                    redirectChain = fallback.analysisBreakdown.redirectChain,
                    visualAnalysis = fallback.analysisBreakdown.visualAnalysis
                ),
                userExplanation = userExplanation,
                recommendation = recommendation,
                evidenceList = fallback.evidenceList,
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
            when {
                status == "BLOCKED" -> {
                    append("BLOCKED: Known malicious destination. Active cyber threat indicators triggered immediate safety block.")
                }
                status == "LIKELY PHISHING" || status == "HIGH RISK" -> {
                    append("CRITICAL: Significant phishing indicators detected (Risk Score: $score/100, ML Probability: ${(mlResult.probability * 100).toInt()}%). ")
                    if (urlAnalysis.hasSubdomainLookalike) {
                        val subMatch = urlAnalysis.subdomainLookalikeMatch
                        if (subMatch != null) {
                            append("SUBDOMAIN SPOOFING: Host contains a deceptive lookalike/typosquat ('${subMatch.candidate}') of official service '${subMatch.targetKeyword}'. A legitimate parent domain does NOT confer safety to lookalike subdomains. ")
                        } else {
                            append("SUBDOMAIN SPOOFING: Host contains an unauthorized lookalike/typosquatted subdomain. ")
                        }
                    }
                    if (urlAnalysis.hasPathAnomaly || urlAnalysis.hasPathLookalike) {
                        append("PATH MANIPULATION: URL path contains a deceptive typo, character manipulation, or lookalike segment imitating an official path. ")
                    }
                    if (urlAnalysis.hasLoginContext && (urlAnalysis.hasSubdomainLookalike || urlAnalysis.hasPathLookalike || urlAnalysis.hasPathAnomaly)) {
                        append("AUTHENTICATION TARGETING: Deceptive structure targets a sensitive login or banking endpoint. ")
                    }
                    if (urlAnalysis.hasPathObfuscation) {
                        append("CRITICAL PATH DECEPTION: URL path employs deceptive leetspeak/character substitution ('l0gin' spoofing 'login'). ")
                    }
                    if (urlAnalysis.hasOpenRedirect) {
                        append("OPEN REDIRECT RISK: URL contains an open redirect parameter pointing traffic to an external target. ")
                    }
                    if (urlAnalysis.hasSuspiciousPayload) {
                        append("DANGEROUS PAYLOAD: URL targets a direct application or executable installer (.apk / .exe). ")
                    }
                    if (brandCheck.isImpersonating) {
                        append("Active brand impersonation targeting ${brandCheck.impersonatedBrand} on unauthorized domain ('${urlAnalysis.cleanHost}'). ")
                    }
                    if (ragResult.matchedCampaignTitle != null && ragResult.highestSimilarity >= 0.25f) {
                        append("Threat matched intelligence profile '${ragResult.matchedCampaignTitle}' (${(ragResult.highestSimilarity * 100).toInt()}% cosine similarity). ")
                    }
                    if (urlAnalysis.isIpAddress) {
                        append("URL uses raw numerical IP address (${urlAnalysis.cleanHost}) bypassing domain reputation filters. ")
                    }
                    if (urlAnalysis.suspiciousTld != null) {
                        append("Domain utilizes an untrusted Top-Level Domain (.${urlAnalysis.suspiciousTld}) heavily associated with scam operations. ")
                    }
                    if (nlpAnalysis.hasUrgency) {
                        append("Accompanying message employs artificial urgency and psychological coercion. ")
                    }
                    append("Do NOT visit this link, enter credentials, or make payments.")
                }
                status == "SUSPICIOUS" -> {
                    append("SUSPICIOUS: Moderate anomaly patterns detected (Risk Score: $score/100). ")
                    if (urlAnalysis.hasPathLookalike || urlAnalysis.hasPathAnomaly) {
                        append("Suspicious lookalike path or typo detected on '${urlAnalysis.cleanHost}'. Verify the specific URL path before interacting. ")
                    } else if (urlAnalysis.hasPathObfuscation) {
                        append("Deceptive character substitution / leetspeak detected in URL path. ")
                    } else if (urlAnalysis.hasOpenRedirect) {
                        append("Open redirect destination detected in URL query. ")
                    } else if (urlAnalysis.detectedThreats.isNotEmpty()) {
                        append("Indicators identified: ${urlAnalysis.detectedThreats.first()}. ")
                    }
                    if (nlpAnalysis.hasUrgency) {
                        append("Context message employs urgency tactics. ")
                    }
                    append("Exercise caution and verify directly through the official provider before opening.")
                }
                else -> {
                    if (isWhitelisted) {
                        append("LOW RISK: The domain '${urlAnalysis.cleanHost}' is verified as an official entity (${whitelistBrand ?: "Verified Authority"}). Standard cybersecurity checks found no deceptive manipulation. Note: Always verify the exact sender.")
                    } else {
                        append("LOW RISK: Multi-layer cybersecurity analysis (ML probability ${(mlResult.probability * 100).toInt()}%, 0 active threats) found no deceptive patterns or malicious signatures for '${urlAnalysis.cleanHost}'. Note: Absence of detected threats does not guarantee absolute safety; always practice standard cybersecurity hygiene.")
                    }
                }
            }
        }
    }

    private fun buildGeminiPrompt(
        url: String,
        contextText: String,
        urlAnalysis: UrlStructureAnalysisResult,
        brandCheck: BrandImpersonationResult,
        threatIntel: ThreatIntelResult,
        isWhitelisted: Boolean,
        whitelistBrand: String?,
        mlResult: MlInferenceResult,
        ragResult: RagRetrievalResult,
        nlpAnalysis: NlpAnalysisResult,
        localThreats: List<String>,
        localScore: Int
    ): String {
        // Redact any session identifiers or sensitive token parameters before transmitting to external AI
        val redactedQuery = PathAnomalyDetector.redactSensitiveQueryParams(urlAnalysis.query)
        val sanitizedUrl = if (urlAnalysis.query.isNotBlank() && redactedQuery.isNotBlank()) {
            val base = url.substringBefore('?')
            "$base?$redactedQuery"
        } else {
            url
        }

        return """
Evaluate the following URL and message context for phishing, scam, and brand impersonation threats:

TARGET URL DETAILS:
- Full URL: $sanitizedUrl
- Scheme: ${urlAnalysis.scheme}
- Clean Host: ${urlAnalysis.cleanHost}
- Root Domain: ${urlAnalysis.rootDomain}
- Path: ${urlAnalysis.path}
- Query: $redactedQuery
- Raw IP Host: ${urlAnalysis.isIpAddress}
- Suspicious TLD: ${urlAnalysis.suspiciousTld ?: "None"}
- Hyphen Count: ${urlAnalysis.hasHyphenStuffing}
- URL Shortener: ${urlAnalysis.isShortener}
- High Shannon Entropy: ${urlAnalysis.highEntropy}
- Punycode/IDN: ${urlAnalysis.isPunycode}
- Path Leetspeak Obfuscation: ${urlAnalysis.hasPathObfuscation}
- Path Lookalike / Typo Manipulation: ${urlAnalysis.hasPathLookalike}
- Open Redirect Parameter: ${urlAnalysis.hasOpenRedirect}
- Executable Download (.apk/.exe): ${urlAnalysis.hasSuspiciousPayload}

WHITELIST & BRAND IMPERSONATION RADAR:
- Whitelist Database Match: ${if (isWhitelisted) "Match Found ($whitelistBrand)" else "No Match"}
- Brand Impersonation Detected: ${brandCheck.isImpersonating}
${if (brandCheck.isImpersonating) "- Impersonated Brand: ${brandCheck.impersonatedBrand} (Official Domain: ${brandCheck.legitimateDomain}, Severity: ${brandCheck.mismatchSeverity})" else "- No brand spoofing detected."}

LOCAL THREAT INTELLIGENCE:
- Reputation Score: ${threatIntel.reputationScore} / 100
- Matched Campaigns: ${if (threatIntel.matchedCampaigns.isEmpty()) "None" else threatIntel.matchedCampaigns.joinToString("; ")}
- Signatures: ${if (threatIntel.threatSignatures.isEmpty()) "None" else threatIntel.threatSignatures.joinToString("; ")}

EXECUTED MACHINE LEARNING INFERENCE:
- Model: Supervised Logistic Regression Classifier (24 features, L2 regularized, version ${mlResult.modelVersion})
- Inferred Probability P(Phishing): ${"%.4f".format(mlResult.probability)} (${"%.1f".format(mlResult.probability * 100)}%)
- Confidence Level: ${"%.1f".format(mlResult.confidencePercentage)}%
- Top ML Contributing Features:
${mlResult.topContributors.take(5).joinToString("\n") { "  * ${it.description} (Contribution: ${"%.3f".format(it.contribution)}, Raw Value: ${"%.2f".format(it.rawValue)})" }}

RETRIEVAL-AUGMENTED INTELLIGENCE (RAG):
${ragResult.ragContextForPrompt}

NLP SEMANTIC & PSYCHOLOGICAL COERCION ANALYSIS:
- Message Context: ${if (contextText.isBlank()) "None provided" else contextText}
- Urgency Pressure Score: ${nlpAnalysis.urgencyScore} / 100
- Imperative Command Ratio: ${"%.1f".format(nlpAnalysis.imperativeRatio * 100)}%
- Pressure Tactics: ${if (nlpAnalysis.pressureTactics.isEmpty()) "None" else nlpAnalysis.pressureTactics.joinToString("; ")}
- Obfuscation / Zero-width / Homoglyphs: ${nlpAnalysis.hasObfuscation}

PRELIMINARY LOCAL DETERMINISTIC THREAT SIGNALS:
- Detected Threats: ${if (localThreats.isEmpty()) "None" else localThreats.joinToString("; ")}
- Composite Local Score: $localScore / 100

MANDATORY EVIDENCE CONSTRAINTS:
1. Reason strictly from the supplied technical evidence above. Do NOT invent external breach reports, news, or unverified claims.
2. If evidence is insufficient or inconclusive, explicitly state that in the user_explanation.
3. Whitelisted domains are NEVER safe if path tampering (e.g., /l0gin, open redirect, .apk payload) is present.
4. If an untrusted domain impersonates a brand (e.g. sbi-kyc-update.xyz, hdfc-netbanking.buzz), classify as PHISHING (risk_score 75-100).
5. If the URL is a verified institutional portal without path tampering, classify as Safe (risk_score 0-10).

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
