package com.example.domain

import kotlin.math.log2
import kotlin.math.min
import kotlin.math.roundToInt

data class CoercionDimension(
    val dimensionName: String,
    val score: Float, // 0.0 to 1.0
    val matchedTerms: List<String>,
    val description: String
)

data class NlpAnalysisResult(
    val hasUrgency: Boolean,
    val urgencyScore: Int, // 0 to 100
    val imperativeRatio: Float, // 0.0 to 1.0 (proportion of sentences formatted as direct commands)
    val lexicalDiversity: Float, // Type-Token Ratio
    val semanticEntropy: Float,
    val detectedKeywords: List<String>,
    val pressureTactics: List<String>,
    val dimensions: List<CoercionDimension>,
    val explanation: String
)

/**
 * Real NLP Semantic & Psychological Coercion Analyzer.
 *
 * Evaluates linguistic characteristics, imperative syntactic mood,
 * lexical diversity, and multi-dimensional psychological persuasion vectors:
 * 1. Temporal Deadline Intensity (artificial urgency to inhibit critical thinking)
 * 2. Punitive Loss Aversion (threat of account suspension, disconnection, legal penalty)
 * 3. Credential Exfiltration Intent (demanding OTP, PAN, PIN, seed phrase)
 * 4. Greed & Bait Manipulation (lottery, reward points, free airdrop)
 */
object NlpSemanticAnalyzer {

    // Imperative verbs that command user action when appearing at clause starts
    private val IMPERATIVE_VERBS = setOf(
        "click", "pay", "verify", "update", "confirm", "open", "call", "send",
        "submit", "claim", "install", "download", "enter", "transfer", "activate",
        "connect", "resolve", "settle", "link", "log", "login", "authenticate"
    )

    // Dimension 1: Temporal Pressure Lexicon
    private val TEMPORAL_LEXICON = mapOf(
        "24 hours" to 0.9f, "24h" to 0.9f, "immediately" to 0.85f, "urgent" to 0.8f,
        "urgently" to 0.85f, "today only" to 0.75f, "within" to 0.6f, "tonight" to 0.7f,
        "asap" to 0.8f, "now" to 0.65f, "immediate" to 0.8f, "deadline" to 0.8f,
        "final notice" to 0.95f, "last reminder" to 0.9f, "expired" to 0.75f,
        "minutes" to 0.7f, "action required" to 0.85f
    )

    // Dimension 2: Punitive Loss Aversion Lexicon
    private val PUNITIVE_LEXICON = mapOf(
        "suspended" to 0.9f, "blocked" to 0.9f, "frozen" to 0.9f, "locked" to 0.85f,
        "disconnected" to 0.9f, "terminated" to 0.9f, "disabled" to 0.8f, "penalty" to 0.85f,
        "legal action" to 0.95f, "destroyed" to 0.9f, "cancelled" to 0.8f, "arrest" to 0.95f,
        "fine" to 0.7f, "closed" to 0.8f, "restricted" to 0.85f, "deactivated" to 0.85f
    )

    // Dimension 3: Credential Exfiltration Lexicon
    private val EXFILTRATION_LEXICON = mapOf(
        "otp" to 0.95f, "pan card" to 0.9f, "pan" to 0.8f, "aadhaar" to 0.85f,
        "password" to 0.9f, "passcode" to 0.9f, "seed phrase" to 1.0f, "recovery phrase" to 1.0f,
        "private key" to 1.0f, "cvv" to 0.95f, "pin" to 0.85f, "credentials" to 0.9f,
        "kyc" to 0.85f, "bank account" to 0.75f, "card number" to 0.9f
    )

    // Dimension 4: Greed & Bait Lexicon
    private val BAIT_LEXICON = mapOf(
        "airdrop" to 0.9f, "lottery" to 0.95f, "reward" to 0.8f, "reward points" to 0.85f,
        "cashback" to 0.8f, "winner" to 0.9f, "congratulations" to 0.85f, "won" to 0.85f,
        "free" to 0.7f, "subsidy" to 0.75f, "bonus" to 0.8f, "usdt" to 0.85f, "gift" to 0.75f
    )

    private fun calculateEntropy(text: String): Float {
        if (text.isEmpty()) return 0.0f
        val freq = mutableMapOf<Char, Int>()
        for (c in text) freq[c] = (freq[c] ?: 0) + 1
        var ent = 0.0
        val len = text.length.toDouble()
        for (cnt in freq.values) {
            val p = cnt.toDouble() / len
            ent -= p * log2(p)
        }
        return ent.toFloat()
    }

    private fun evaluateLexicon(textLower: String, lexicon: Map<String, Float>): Pair<Float, List<String>> {
        val matched = mutableListOf<String>()
        var totalWeight = 0.0f
        for ((term, weight) in lexicon) {
            if (textLower.contains(term)) {
                matched.add(term)
                totalWeight += weight
            }
        }
        val score = min(1.0f, totalWeight)
        return Pair(score, matched)
    }

    fun analyze(contextText: String): NlpAnalysisResult {
        val trimmed = contextText.trim()
        if (trimmed.isBlank()) {
            return NlpAnalysisResult(
                hasUrgency = false,
                urgencyScore = 0,
                imperativeRatio = 0.0f,
                lexicalDiversity = 1.0f,
                semanticEntropy = 0.0f,
                detectedKeywords = emptyList(),
                pressureTactics = emptyList(),
                dimensions = emptyList(),
                explanation = "No contextual message provided for NLP analysis."
            )
        }

        val textLower = trimmed.lowercase()

        // 1. Syntactic clause & sentence splitting
        val sentences = trimmed.split(Regex("[.!?\n]+")).map { it.trim() }.filter { it.isNotEmpty() }
        val sentenceCount = maxOf(1, sentences.size)
        var imperativeCount = 0

        for (sentence in sentences) {
            val firstWord = sentence.split(Regex("\\s+")).firstOrNull()?.lowercase() ?: ""
            if (IMPERATIVE_VERBS.contains(firstWord)) {
                imperativeCount++
            }
        }
        val imperativeRatio = (imperativeCount.toFloat() / sentenceCount.toFloat()).coerceIn(0.0f, 1.0f)

        // 2. Lexical diversity (Type-Token Ratio)
        val tokens = textLower.split(Regex("[^a-zA-Z0-9]+")).filter { it.length > 1 }
        val totalTokens = maxOf(1, tokens.size)
        val uniqueTokens = tokens.toSet().size
        val lexicalDiversity = (uniqueTokens.toFloat() / totalTokens.toFloat()).coerceIn(0.0f, 1.0f)
        val entropy = calculateEntropy(textLower)

        // 3. Multi-dimensional psychological evaluation
        val (temporalScore, temporalMatches) = evaluateLexicon(textLower, TEMPORAL_LEXICON)
        val (punitiveScore, punitiveMatches) = evaluateLexicon(textLower, PUNITIVE_LEXICON)
        val (exfilScore, exfilMatches) = evaluateLexicon(textLower, EXFILTRATION_LEXICON)
        val (baitScore, baitMatches) = evaluateLexicon(textLower, BAIT_LEXICON)

        val dimensions = mutableListOf<CoercionDimension>()
        val tactics = mutableListOf<String>()
        val allKeywords = mutableListOf<String>()

        if (temporalMatches.isNotEmpty()) {
            dimensions.add(
                CoercionDimension(
                    dimensionName = "Temporal Deadline Pressure",
                    score = temporalScore,
                    matchedTerms = temporalMatches,
                    description = "Fabricates tight deadline to prevent careful verification"
                )
            )
            tactics.add("Artificial Deadline Pressure (${temporalMatches.joinToString(", ")})")
            allKeywords.addAll(temporalMatches)
        }

        if (punitiveMatches.isNotEmpty()) {
            dimensions.add(
                CoercionDimension(
                    dimensionName = "Punitive Loss Aversion",
                    score = punitiveScore,
                    matchedTerms = punitiveMatches,
                    description = "Threatens immediate suspension, penalty, or service disconnection"
                )
            )
            tactics.add("Account / Service Suspension Threat (${punitiveMatches.joinToString(", ")})")
            allKeywords.addAll(punitiveMatches)
        }

        if (exfilMatches.isNotEmpty()) {
            dimensions.add(
                CoercionDimension(
                    dimensionName = "Credential Exfiltration Lure",
                    score = exfilScore,
                    matchedTerms = exfilMatches,
                    description = "Solicits high-privilege credentials, OTP, or identity documents"
                )
            )
            tactics.add("Sensitive Credential Harvesting (${exfilMatches.joinToString(", ")})")
            allKeywords.addAll(exfilMatches)
        }

        if (baitMatches.isNotEmpty()) {
            dimensions.add(
                CoercionDimension(
                    dimensionName = "Bait & Greed Manipulation",
                    score = baitScore,
                    matchedTerms = baitMatches,
                    description = "Promises free rewards, prizes, or token airdrops"
                )
            )
            tactics.add("Financial Bait / Airdrop Incentive (${baitMatches.joinToString(", ")})")
            allKeywords.addAll(baitMatches)
        }

        // Composite continuous urgency score (0 to 100)
        // Primary dominant threat vector + secondary vectors + imperative modifier
        val maxDim = maxOf(temporalScore, punitiveScore, exfilScore, baitScore)
        val secondarySum = (temporalScore + punitiveScore + exfilScore + baitScore - maxDim).coerceAtLeast(0.0f) * 0.25f
        val imperativeBonus = imperativeRatio * 0.20f
        val weightedSum = (maxDim * 0.65f) + secondarySum + imperativeBonus

        val rawUrgencyScore = (weightedSum * 100.0f).roundToInt().coerceIn(0, 100)
        val hasUrgency = rawUrgencyScore >= 25 || tactics.isNotEmpty()

        val explanation = buildString {
            if (tactics.isEmpty()) {
                append("NLP semantic analysis evaluated text as neutral with standard imperative ratio (${"%.0f".format(imperativeRatio * 100)}%). No psychological coercion tactics detected.")
            } else {
                append("NLP engine flagged ${tactics.size} psychological coercion vector(s): ")
                append(tactics.joinToString("; "))
                append(". Imperative command structure: ${"%.0f".format(imperativeRatio * 100)}% of sentences.")
            }
        }

        return NlpAnalysisResult(
            hasUrgency = hasUrgency,
            urgencyScore = rawUrgencyScore,
            imperativeRatio = imperativeRatio,
            lexicalDiversity = lexicalDiversity,
            semanticEntropy = entropy,
            detectedKeywords = allKeywords.distinct(),
            pressureTactics = tactics,
            dimensions = dimensions,
            explanation = explanation
        )
    }
}
