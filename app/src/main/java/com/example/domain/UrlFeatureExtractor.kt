package com.example.domain

import java.net.URI
import java.util.regex.Pattern
import kotlin.math.log2
import kotlin.math.max
import kotlin.math.min

/**
 * Real Quantitative Feature Extractor for URL Phishing Classification.
 * Extracts a 36-dimensional feature vector measuring lexical, syntactic,
 * information-theoretic (Shannon entropy), path anomaly, and structural properties.
 */
data class ExtractedUrlFeatures(
    val url: String,
    val vector: FloatArray,
    val featureMap: Map<String, Float>,
    val host: String,
    val path: String,
    val query: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ExtractedUrlFeatures
        return url == other.url && vector.contentEquals(other.vector)
    }

    override fun hashCode(): Int {
        var result = url.hashCode()
        result = 31 * result + vector.contentHashCode()
        return result
    }
}

object UrlFeatureExtractor {

    val FEATURE_NAMES = listOf(
        "urlLength", "hostLength", "pathLength", "queryLength", "dotCount",
        "hyphenCount", "slashCount", "questionMarkCount", "equalCount", "atSymbolCount",
        "ampersandCount", "digitCount", "hostDigitCount", "digitRatio", "isHttps",
        "isIpAddress", "subdomainCount", "hasCustomPort", "hostEntropy", "pathEntropy",
        "tldAbuseRisk", "phishingKeywordCount", "tokenCount", "longestTokenLength",
        "pathSegmentCount", "suspiciousPathTokenCount", "typoCount", "charSubstitutionCount",
        "repeatedCharCount", "homoglyphCount", "encodedCharCount", "loginAuthKeywordPresence",
        "trustedDomainPathAnomaly", "queryComplexity", "hasNestedUrlOrRedirect", "domainPathMismatch"
    )

    private val IP_PATTERN = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$")

    private val HIGH_RISK_TLDS = setOf(
        "top", "xyz", "icu", "buzz", "tk", "ml", "ga", "cf", "gq",
        "work", "click", "download", "racing", "men", "club", "surf",
        "vip", "rest", "cam", "fit", "sbs", "cfd", "monster", "uno",
        "pw", "cc", "ws", "trade", "bid", "loan", "date", "review",
        "zip", "mov", "kim", "party", "science", "stream", "gdn",
        "mom", "lol", "quest", "cyou", "host", "link", "shop", "live",
        "site", "online"
    )

    private val PHISHING_KEYWORDS = listOf(
        "login", "signin", "logon", "auth", "authenticate", "sso",
        "verify", "verification", "secure", "security", "update",
        "wallet", "kyc", "otp", "passcode", "password", "airdrop",
        "drainer", "redelivery", "account", "banking", "pan", "aadhaar",
        "claim", "refund", "invoice", "payment", "parcel", "delivery"
    )

    private val AUTH_KEYWORDS = listOf(
        "login", "signin", "auth", "authenticate", "account", "banking", "retail", "kyc", "otp", "password", "verify"
    )

    private val COMMON_BRANDS = listOf(
        "sbi", "paypal", "google", "netflix", "facebook", "instagram", "chase", "hdfc", "icici", "apple", "amazon"
    )

    private val HOMOGLYPH_CHARS = setOf(
        'а', 'е', 'і', 'о', 'р', 'с', 'у', 'х', 'ӏ', 'α', 'ο', 'ν', 'ѕ', 'ԁ', 'ԝ',
        'А', 'В', 'Е', 'К', 'М', 'Н', 'О', 'Р', 'С', 'Т', 'Х'
    )

    fun calculateShannonEntropy(str: String): Float {
        if (str.isEmpty()) return 0.0f
        val freq = mutableMapOf<Char, Int>()
        for (ch in str) {
            freq[ch] = (freq[ch] ?: 0) + 1
        }
        var entropy = 0.0
        val len = str.length.toDouble()
        for (count in freq.values) {
            val p = count.toDouble() / len
            entropy -= p * (log2(p))
        }
        return entropy.toFloat()
    }

    fun extract(rawUrl: String): ExtractedUrlFeatures {
        val trimmed = rawUrl.trim()
        val isHttps = if (trimmed.startsWith("https://", ignoreCase = true)) 1.0f else 0.0f

        val cleanNoScheme = trimmed.replace(Regex("^https?://", RegexOption.IGNORE_CASE), "")
        val slashIndex = cleanNoScheme.indexOf('/')
        val hostAndPort = if (slashIndex != -1) cleanNoScheme.substring(0, slashIndex) else cleanNoScheme
        val pathAndQuery = if (slashIndex != -1) cleanNoScheme.substring(slashIndex) else ""

        val hostParts = hostAndPort.split(":")
        val host = hostParts[0].lowercase().trim()
        val hasCustomPort = if (hostParts.size > 1 && hostParts[1] !in listOf("80", "443", "")) 1.0f else 0.0f

        val qIndex = pathAndQuery.indexOf('?')
        val path = if (qIndex != -1) pathAndQuery.substring(0, qIndex) else pathAndQuery
        val query = if (qIndex != -1) pathAndQuery.substring(qIndex + 1) else ""

        // 1. urlLength
        val f1 = trimmed.length.toFloat()
        // 2. hostLength
        val f2 = host.length.toFloat()
        // 3. pathLength
        val f3 = path.length.toFloat()
        // 4. queryLength
        val f4 = query.length.toFloat()
        // 5. dotCount
        val f5 = trimmed.count { it == '.' }.toFloat()
        // 6. hyphenCount
        val f6 = trimmed.count { it == '-' }.toFloat()
        // 7. slashCount
        val f7 = path.count { it == '/' }.toFloat()
        // 8. questionMarkCount
        val f8 = trimmed.count { it == '?' }.toFloat()
        // 9. equalCount
        val f9 = query.count { it == '=' }.toFloat()
        // 10. atSymbolCount
        val f10 = trimmed.count { it == '@' }.toFloat()
        // 11. ampersandCount
        val f11 = trimmed.count { it == '&' }.toFloat()
        // 12. digitCount
        val f12 = trimmed.count { it.isDigit() }.toFloat()
        // 13. hostDigitCount
        val f13 = host.count { it.isDigit() }.toFloat()
        // 14. digitRatio
        val f14 = if (trimmed.isNotEmpty()) f12 / trimmed.length.toFloat() else 0.0f
        // 15. isHttps
        val f15 = isHttps
        // 16. isIpAddress
        val f16 = if (IP_PATTERN.matcher(host).matches()) 1.0f else 0.0f
        // 17. subdomainCount
        val subdomains = max(0, host.split(".").size - 2).toFloat()
        val f17 = subdomains
        // 18. hasCustomPort
        val f18 = hasCustomPort
        // 19. hostEntropy
        val f19 = calculateShannonEntropy(host)
        // 20. pathEntropy
        val f20 = calculateShannonEntropy(path)
        // 21. tldAbuseRisk
        val tld = if (host.contains(".")) host.substringAfterLast(".").lowercase() else ""
        val f21 = when {
            HIGH_RISK_TLDS.contains(tld) -> 1.0f
            tld in listOf("gov", "edu") || host.endsWith(".bank.in") || host.endsWith(".gov.in") -> -0.5f
            else -> 0.0f
        }
        // 22. phishingKeywordCount
        val lowUrl = trimmed.lowercase()
        val f22 = PHISHING_KEYWORDS.count { lowUrl.contains(it) }.toFloat()
        // 23. tokenCount
        val tokens = cleanNoScheme.split(Regex("[./\\-_?=&]")).filter { it.isNotBlank() }
        val f23 = tokens.size.toFloat()
        // 24. longestTokenLength
        val f24 = (tokens.maxOfOrNull { it.length } ?: 0).toFloat()

        // 25. pathSegmentCount
        val pathSegments = path.split("/").filter { it.isNotBlank() }
        val f25 = pathSegments.size.toFloat()

        // Path Anomaly & Typo analysis
        var typoCount = 0
        var repeatedCharCount = 0
        var leetCount = 0
        var suspiciousPathTokens = 0

        // 30. homoglyphCount
        val f30 = trimmed.count { HOMOGLYPH_CHARS.contains(it) }.toFloat()

        // 31. encodedCharCount
        val f31 = trimmed.count { it == '%' }.toFloat()

        // 32. loginAuthKeywordPresence
        val f32 = if (AUTH_KEYWORDS.any { lowUrl.contains(it) }) 1.0f else 0.0f

        // 33. trustedDomainPathAnomaly
        val isTrustedHost = host == "instagram.com" || host.endsWith(".instagram.com") ||
                host == "onlinesbi.sbi" || host.endsWith(".onlinesbi.sbi") ||
                host == "google.com" || host.endsWith(".google.com") ||
                host == "paypal.com" || host.endsWith(".paypal.com")

        var trustedAnomaly = 0.0f

        for (seg in pathSegments) {
            val segLower = seg.lowercase().substringBefore('.').substringBefore('?')
            // Repeated char / stuttering
            if (segLower.length >= 4) {
                val sb = StringBuilder()
                for (i in segLower.indices) {
                    if (i == 0 || segLower[i] != segLower[i - 1]) sb.append(segLower[i])
                }
                val collapsed = sb.toString()
                if (collapsed in listOf("rel", "login", "bank", "pay")) {
                    repeatedCharCount++
                    typoCount++
                    suspiciousPathTokens++
                    if (isTrustedHost) trustedAnomaly = 1.0f
                }
            }

            // Transposition (e.g. retial -> retail)
            if (segLower in listOf("retial", "logni", "bnak", "acocunt")) {
                typoCount++
                suspiciousPathTokens++
                if (isTrustedHost) trustedAnomaly = 1.0f
            }

            // Leetspeak
            if (segLower.any { it.isDigit() || it == '@' || it == '$' }) {
                val deleet = segLower.replace('0', 'o').replace('1', 'l').replace('3', 'e')
                    .replace('4', 'a').replace('5', 's').replace('7', 't').replace('8', 'b')
                    .replace('@', 'a').replace('$', 's')
                if (AUTH_KEYWORDS.any { deleet.contains(it) }) {
                    leetCount++
                    suspiciousPathTokens++
                }
            }
        }

        // Check host for lookalikes (e.g. retaii vs retail)
        if (host.contains("retaii") || host.contains("paypai") || trimmed.contains("googIe")) {
            typoCount++
        }

        val f26 = suspiciousPathTokens.toFloat()
        val f27 = typoCount.toFloat()
        val f28 = leetCount.toFloat()
        val f29 = repeatedCharCount.toFloat()
        val f33 = trustedAnomaly

        // 34. queryComplexity
        val qParams = query.split('&').filter { it.isNotBlank() }
        val qComp = (qParams.size * 0.2f + (if (query.contains("%25")) 0.5f else 0.0f) + (if (query.length > 50) 0.3f else 0.0f))
        val f34 = min(qComp, 1.0f)

        // 35. hasNestedUrlOrRedirect
        val qLow = query.lowercase()
        val f35 = if (qLow.contains("http://") || qLow.contains("https://") ||
            qLow.contains("redirect=") || qLow.contains("url=") || qLow.contains("next=") || qLow.contains("dest=")
        ) 1.0f else 0.0f

        // 36. domainPathMismatch
        val hasBrandInPath = COMMON_BRANDS.any { path.lowercase().contains(it) }
        val isBrandHost = COMMON_BRANDS.any { host.contains(it) }
        val f36 = if (hasBrandInPath && !isBrandHost && !isTrustedHost) 1.0f else 0.0f

        val vector = floatArrayOf(
            f1, f2, f3, f4, f5, f6, f7, f8, f9, f10,
            f11, f12, f13, f14, f15, f16, f17, f18, f19, f20,
            f21, f22, f23, f24, f25, f26, f27, f28, f29, f30,
            f31, f32, f33, f34, f35, f36
        )

        val featureMap = FEATURE_NAMES.indices.associate { i ->
            FEATURE_NAMES[i] to vector[i]
        }

        return ExtractedUrlFeatures(
            url = trimmed,
            vector = vector,
            featureMap = featureMap,
            host = host,
            path = path,
            query = query
        )
    }
}
