package com.example.domain

data class NlpAnalysisResult(
    val hasUrgency: Boolean,
    val urgencyScore: Int, // 0 to 100
    val detectedKeywords: List<String>,
    val pressureTactics: List<String>,
    val explanation: String
)

object NlpSemanticAnalyzer {

    private val URGENCY_TRIGGERS = listOf(
        Regex("""(?i)\b(within\s+\d+\s*(hours?|hrs?|mins?|minutes?|days?|seconds?))\b""") to "Strict artificial deadline pressure",
        Regex("""(?i)\b(package\s+(cannot\s+be|could\s+not\s+be|failed\s+to\s+be)\s+delivered|failed\s+delivery|undelivered\s+(parcel|package|item)|delivery\s+failed|incomplete\s+address|missing\s+street\s+number)\b""") to "Postal delivery failure pretext",
        Regex("""(?i)\b(update\s+(your\s+)?address|confirm\s+(your\s+)?address|reschedule\s+delivery|pay\s+redelivery\s+fee|customs\s+duty\s+pending)\b""") to "Address update / Customs fee lure",
        Regex("""(?i)\b(account\s+(has\s+been\s+)?(suspended|locked|terminated|blocked|frozen|disabled|restricted|deactivated|closed))\b""") to "Account suspension panic tactic",
        Regex("""(?i)\b(action\s+required|urgent|immediate\s+action|act\s+now|immediately|asap|within\s+24h|today\s+only|final\s+notice|last\s+reminder)\b""") to "High-urgency psychological coercion",
        Regex("""(?i)\b(unauthorized\s+(transaction|login|access|activity|charge|transfer|withdrawal))\b""") to "Security scare & fake fraud alert",
        Regex("""(?i)\b(verify\s+(your\s+)?(kyc|identity|account|pan|aadhaar|credentials|password|card|billing|ssn))\b""") to "Identity / KYC / Credential harvesting prompt",
        Regex("""(?i)\b(returned\s+to\s+sender|will\s+be\s+destroyed|cancelled|permanent\s+loss|account\s+deletion)\b""") to "Consequence threat pressure",
        Regex("""(?i)\b(claim\s+(your\s+)?(reward|prize|refund|bonus|crypto|airdrop|gift|voucher|cash|tax\s+refund))\b""") to "Financial bait & greed trigger",
        Regex("""(?i)\b(payment\s+failed|declined|membership\s+on\s+hold|billing\s+problem|subscription\s+cancelled|invoice\s+overdue)\b""") to "Subscription / Payment failure pretext",
        Regex("""(?i)\b(seed\s+phrase|secret\s+recovery\s+phrase|private\s+key|enter\s+12\s+words|connect\s+wallet)\b""") to "Web3 seed phrase theft pattern"
    )

    fun analyze(contextText: String): NlpAnalysisResult {
        if (contextText.isBlank()) {
            return NlpAnalysisResult(
                hasUrgency = false,
                urgencyScore = 0,
                detectedKeywords = emptyList(),
                pressureTactics = emptyList(),
                explanation = "No contextual text provided for NLP evaluation."
            )
        }

        val foundTactics = mutableListOf<String>()
        val foundKeywords = mutableListOf<String>()
        var score = 0

        for ((regex, tacticName) in URGENCY_TRIGGERS) {
            val matches = regex.findAll(contextText).toList()
            if (matches.isNotEmpty()) {
                foundTactics.add(tacticName)
                matches.forEach { foundKeywords.add(it.value.trim()) }
                score += 30
            }
        }

        score = score.coerceIn(0, 100)
        val hasUrgency = score >= 25

        val explanation = buildString {
            if (foundTactics.isEmpty()) {
                append("NLP analysis found neutral tone with no high-urgency psychological pressure tactics.")
            } else {
                append("Detected ${foundTactics.size} psychological pressure tactic(s): ")
                append(foundTactics.distinct().joinToString(", "))
                append(". Key urgency phrases: ")
                append(foundKeywords.distinct().take(4).joinToString { "\"$it\"" })
                append(".")
            }
        }

        return NlpAnalysisResult(
            hasUrgency = hasUrgency,
            urgencyScore = score,
            detectedKeywords = foundKeywords.distinct(),
            pressureTactics = foundTactics.distinct(),
            explanation = explanation
        )
    }
}
