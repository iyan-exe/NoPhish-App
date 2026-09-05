package com.example.domain

import java.text.Normalizer
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
    val hasObfuscation: Boolean = false,
    val detectedKeywords: List<String>,
    val pressureTactics: List<String>,
    val dimensions: List<CoercionDimension>,
    val explanation: String
)

/**
 * Statistical and Rule-Based Semantic NLP Analysis Engine.
 *
 * NOTE: This is a specialized statistical and rule-based linguistic analyzer,
 * NOT a deep neural network or LLM. It computes:
 * 1. Safe Unicode NFKC normalization and HTML tag extraction
 * 2. Obfuscation detection: zero-width spaces, mixed scripts, and homoglyph mapping
 * 3. Syntactic imperative clause analysis (command structure ratio)
 * 4. Information-theoretic Shannon entropy & lexical diversity (Type-Token Ratio)
 * 5. Multi-vector psychological coercion profiling:
 *    - Temporal Deadline Intensity (artificial urgency)
 *    - Punitive Loss Aversion (account suspended, legal penalty, disconnection)
 *    - Sensitive Credential Exfiltration (OTP, password, seed phrase, PAN, PIN)
 *    - Greed / Reward / Scam Bait Manipulation (lottery, airdrop, free cashback)
 */
object NlpSemanticAnalyzer {

    // Imperative verbs that command user action when appearing at clause starts
    private val IMPERATIVE_VERBS = setOf(
        "click", "pay", "verify", "update", "confirm", "open", "call", "send",
        "submit", "claim", "install", "download", "enter", "transfer", "activate",
        "connect", "resolve", "settle", "link", "log", "login", "authenticate",
        "complete", "provide", "renew", "unlock", "restore", "validate", "upgrade"
    )

    // Hidden zero-width characters commonly abused to bypass regex and keyword filters
    private val ZERO_WIDTH_CHARS = setOf(
        '\u200B', '\u200C', '\u200D', '\uFEFF', '\u200E', '\u200F', '\u00AD', '\u202A', '\u202B', '\u202C', '\u202D', '\u202E'
    )

    // Common Cyrillic & Greek homoglyphs mapped to Latin equivalents for keyword detection
    private val HOMOGLYPH_MAP = mapOf(
        'а' to 'a', 'е' to 'e', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'у' to 'y', 'х' to 'x',
        'і' to 'i', 'ј' to 'j', 'ѕ' to 's', 'ԁ' to 'd', 'ԛ' to 'q', 'ԝ' to 'w',
        'А' to 'a', 'Е' to 'e', 'О' to 'o', 'Р' to 'p', 'С' to 'c', 'Х' to 'x', 'І' to 'i'
    )

    // Dimension 1: Temporal Pressure Lexicon
    private val TEMPORAL_LEXICON = mapOf(
        "24 hours" to 0.9f, "24h" to 0.9f, "immediately" to 0.85f, "urgent" to 0.8f,
        "urgently" to 0.85f, "today only" to 0.75f, "within" to 0.6f, "tonight" to 0.7f,
        "asap" to 0.8f, "now" to 0.65f, "immediate" to 0.8f, "deadline" to 0.8f,
        "final notice" to 0.95f, "last reminder" to 0.9f, "expired" to 0.75f,
        "minutes" to 0.7f, "action required" to 0.85f, "expiring" to 0.8f,
        "within 1 hour" to 0.95f, "within 2 hours" to 0.9f, "limited time" to 0.75f,
        "act fast" to 0.8f, "instant" to 0.65f
    )

    // Dimension 2: Punitive Loss Aversion Lexicon
    private val PUNITIVE_LEXICON = mapOf(
        "suspended" to 0.9f, "blocked" to 0.9f, "frozen" to 0.9f, "locked" to 0.85f,
        "disconnected" to 0.9f, "terminated" to 0.9f, "disabled" to 0.8f, "penalty" to 0.85f,
        "legal action" to 0.95f, "destroyed" to 0.9f, "cancelled" to 0.8f, "arrest" to 0.95f,
        "fine" to 0.7f, "closed" to 0.8f, "restricted" to 0.85f, "deactivated" to 0.85f,
        "power cut" to 0.9f, "electricity cut" to 0.9f, "warrant" to 0.95f, "court" to 0.85f,
        "prosecution" to 0.9f, "account hold" to 0.85f, "loss of access" to 0.8f
    )

    // Dimension 3: Credential Exfiltration Lexicon
    private val EXFILTRATION_LEXICON = mapOf(
        "otp" to 0.95f, "pan card" to 0.9f, "pan" to 0.8f, "aadhaar" to 0.85f,
        "password" to 0.9f, "passcode" to 0.9f, "seed phrase" to 1.0f, "recovery phrase" to 1.0f,
        "private key" to 1.0f, "cvv" to 0.95f, "pin" to 0.85f, "credentials" to 0.9f,
        "kyc" to 0.85f, "bank account" to 0.75f, "card number" to 0.9f, "secret key" to 1.0f,
        "12 words" to 0.95f, "login credentials" to 0.9f, "security question" to 0.85f,
        "social security" to 0.95f, "ssn" to 0.95f
    )

    // Dimension 4: Greed & Bait Lexicon
    private val BAIT_LEXICON = mapOf(
        "airdrop" to 0.9f, "lottery" to 0.95f, "reward" to 0.8f, "reward points" to 0.85f,
        "cashback" to 0.8f, "winner" to 0.9f, "congratulations" to 0.85f, "won" to 0.85f,
        "free" to 0.7f, "subsidy" to 0.75f, "bonus" to 0.8f, "usdt" to 0.85f, "gift" to 0.75f,
        "free recharge" to 0.9f, "crypto reward" to 0.85f, "claim reward" to 0.85f,
        "prize money" to 0.9f, "unclaimed" to 0.8f
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

        val tactics = mutableListOf<String>()
        val allKeywords = mutableListOf<String>()

        // 1. Obfuscation Check: Hidden zero-width characters
        val hasZeroWidth = trimmed.any { ZERO_WIDTH_CHARS.contains(it) }
        if (hasZeroWidth) {
            tactics.add("Hidden zero-width character evasion detected")
        }

        // 2. Safe Unicode NFKC Normalization & HTML stripping
        val normalizedNfkc = Normalizer.normalize(trimmed, Normalizer.Form.NFKC)
        val cleanText = normalizedNfkc.replace(Regex("<[^>]*>"), " ")
            .filter { !ZERO_WIDTH_CHARS.contains(it) }

        // 3. Obfuscation Check: Cyrillic / Greek Homoglyph substitution
        val hasHomoglyphs = cleanText.any { HOMOGLYPH_MAP.containsKey(it) }
        if (hasHomoglyphs) {
            tactics.add("Confusable homoglyph character mixing detected")
        }

        // Normalize text for semantic matching by de-homoglyphing
        val deHomoglyphed = buildString {
            for (c in cleanText) {
                append(HOMOGLYPH_MAP[c] ?: c)
            }
        }.lowercase()

        // 4. Syntactic clause & sentence splitting
        val sentences = cleanText.split(Regex("[.!?\n]+")).map { it.trim() }.filter { it.isNotEmpty() }
        val sentenceCount = maxOf(1, sentences.size)
        var imperativeCount = 0

        for (sentence in sentences) {
            val firstWord = sentence.split(Regex("\\s+")).firstOrNull()?.lowercase() ?: ""
            if (IMPERATIVE_VERBS.contains(firstWord)) {
                imperativeCount++
            }
        }
        val imperativeRatio = (imperativeCount.toFloat() / sentenceCount.toFloat()).coerceIn(0.0f, 1.0f)

        // 5. Lexical diversity (Type-Token Ratio)
        val tokens = deHomoglyphed.split(Regex("[^a-zA-Z0-9]+")).filter { it.length > 1 }
        val totalTokens = maxOf(1, tokens.size)
        val uniqueTokens = tokens.toSet().size
        val lexicalDiversity = (uniqueTokens.toFloat() / totalTokens.toFloat()).coerceIn(0.0f, 1.0f)
        val entropy = calculateEntropy(deHomoglyphed)

        // 6. Excessive punctuation check (e.g. Urgent Update Needed!!!! Act Now??)
        val excessivePunctuation = Regex("!{3,}|\\?{3,}|[$]{2,}").containsMatchIn(cleanText)
        if (excessivePunctuation) {
            tactics.add("High-intensity coercive punctuation (!!!/???)")
        }

        // 7. Multi-dimensional psychological persuasion vectors
        val (temporalScore, temporalMatches) = evaluateLexicon(deHomoglyphed, TEMPORAL_LEXICON)
        val (punitiveScore, punitiveMatches) = evaluateLexicon(deHomoglyphed, PUNITIVE_LEXICON)
        val (exfilScore, exfilMatches) = evaluateLexicon(deHomoglyphed, EXFILTRATION_LEXICON)
        val (baitScore, baitMatches) = evaluateLexicon(deHomoglyphed, BAIT_LEXICON)

        val dimensions = mutableListOf<CoercionDimension>()

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
        val maxDim = maxOf(temporalScore, punitiveScore, exfilScore, baitScore)
        val secondarySum = (temporalScore + punitiveScore + exfilScore + baitScore - maxDim).coerceAtLeast(0.0f) * 0.25f
        val imperativeBonus = imperativeRatio * 0.20f
        val obfuscationBonus = if (hasZeroWidth || hasHomoglyphs) 0.15f else 0.0f
        val weightedSum = (maxDim * 0.60f) + secondarySum + imperativeBonus + obfuscationBonus

        val rawUrgencyScore = (weightedSum * 100.0f).roundToInt().coerceIn(0, 100)
        val hasUrgency = rawUrgencyScore >= 25 || tactics.isNotEmpty()

        val explanation = buildString {
            if (tactics.isEmpty()) {
                append("Statistical NLP analysis evaluated text as neutral with standard imperative ratio (${"%.0f".format(imperativeRatio * 100)}%). No psychological coercion tactics detected.")
            } else {
                append("Statistical NLP analysis identified ${tactics.size} psychological coercion vector(s): ")
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
            hasObfuscation = hasZeroWidth || hasHomoglyphs,
            detectedKeywords = allKeywords.distinct(),
            pressureTactics = tactics,
            dimensions = dimensions,
            explanation = explanation
        )
    }
}
