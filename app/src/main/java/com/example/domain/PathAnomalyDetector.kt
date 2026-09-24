package com.example.domain

import java.net.URLDecoder
import kotlin.math.abs
import kotlin.math.max

data class PathSegmentAnomaly(
    val rawSegment: String,
    val targetKeyword: String,
    val anomalyType: String, // "CharacterInsertion", "CharacterDeletion", "CharacterSubstitution", "Transposition", "RepeatedCharacter", "VisualLookalike", "Homoglyph", "DigitSubstitution", "SuspiciousCapitalization"
    val description: String,
    val distance: Int,
    val severity: String // "Low", "Medium", "High", "Critical"
)

data class QueryAnalysisResult(
    val hasExcessiveEncoding: Boolean = false,
    val hasSuspiciousRedirect: Boolean = false,
    val hasExternalUrl: Boolean = false,
    val hasJsPayload: Boolean = false,
    val hasSuspiciousParamName: Boolean = false,
    val hasExtremelyLongValue: Boolean = false,
    val hasEncodedDomain: Boolean = false,
    val hasNestedUrl: Boolean = false,
    val isBenignTrackingOrSessionToken: Boolean = false,
    val detectedIssues: List<String> = emptyList(),
    val queryComplexityScore: Float = 0.0f
)

data class PathAnalysisResult(
    val hasPathAnomaly: Boolean,
    val pathAnomalyScore: Int, // 0 to 100
    val anomalies: List<PathSegmentAnomaly>,
    val expectedProfileMatched: String?,
    val isKnownProfileDomain: Boolean,
    val isExpectedProfilePath: Boolean,
    val hasSensitiveTermAnomaly: Boolean,
    val hasNumericSubstitution: Boolean,
    val hasSuspiciousCapitalization: Boolean,
    val hasEncodedPathChars: Boolean,
    val pathSegmentCount: Int,
    val suspiciousPathTokensCount: Int,
    val queryAnalysis: QueryAnalysisResult,
    val detectedThreats: List<String>,
    val explanation: String
)

/**
 * Dedicated URL Path and Query Anomaly Detection Engine.
 *
 * Implements:
 * 1. Known-domain expected path profiling (e.g. Instagram, Banking, Google, PayPal).
 * 2. Generalized typo, edit-distance (Damerau-Levenshtein), transposition, insertion,
 *    and deletion analysis against expected paths and sensitive authentication keywords.
 * 3. Character-level lookalikes, homoglyphs, and numeric/leetspeak substitutions.
 * 4. Query parameter analysis distinguishing benign tracking/session tokens from open redirects/payloads.
 */
object PathAnomalyDetector {

    // Domain-specific expected/canonical top-level paths
    private val DOMAIN_EXPECTED_PATHS = mapOf(
        "instagram.com" to setOf(
            "reel", "reels", "p", "stories", "story", "explore", "accounts",
            "direct", "tv", "tags", "developer", "about", "legal", "api"
        ),
        "onlinesbi.sbi" to setOf(
            "retail", "personal", "corporate", "netbanking", "banking", "login",
            "signin", "auth", "kyc", "portal", "cards", "loans", "services", "accounts"
        ),
        "sbi.co.in" to setOf(
            "retail", "personal", "corporate", "netbanking", "banking", "login",
            "portal", "services", "careers"
        ),
        "paypal.com" to setOf(
            "signin", "login", "myaccount", "checkout", "webapps", "transfer",
            "money", "buttons", "smart", "connect", "invite"
        ),
        "google.com" to setOf(
            "search", "drive", "mail", "maps", "docs", "sheets", "slides",
            "forms", "photos", "calendar", "accounts", "settings", "url"
        ),
        "twitter.com" to setOf(
            "home", "explore", "notifications", "messages", "settings", "i", "search"
        ),
        "x.com" to setOf(
            "home", "explore", "notifications", "messages", "settings", "i", "search"
        ),
        "facebook.com" to setOf(
            "login", "groups", "watch", "marketplace", "gaming", "settings", "profile.php", "recover"
        ),
        "youtube.com" to setOf(
            "watch", "shorts", "feed", "channel", "playlist", "results", "trending"
        ),
        "netflix.com" to setOf(
            "browse", "login", "title", "search", "youraccount"
        ),
        "amazon.com" to setOf(
            "dp", "gp", "s", "cart", "your-account", "orders", "b", "deal"
        ),
        "linkedin.com" to setOf(
            "feed", "in", "jobs", "messaging", "notifications", "company"
        ),
        "github.com" to setOf(
            "login", "explore", "trending", "settings", "pulls", "issues", "marketplace"
        )
    )

    // Common sensitive terms targeted by attackers across arbitrary domains
    val SENSITIVE_PATH_TERMS = listOf(
        "login", "signin", "sign-in", "signon", "auth", "authenticate", "sso",
        "verify", "verification", "password", "passcode", "account", "accounts",
        "wallet", "kyc", "otp", "banking", "netbanking", "retail", "personal",
        "corporate", "security", "secure", "update", "credit", "debit", "card",
        "confirm", "validation", "portal", "admin", "payment", "payments"
    )

    // Benign standard English and web words that must NOT be flagged as typos of sensitive terms
    val BENIGN_PATH_WORDS = setOf(
        "detail", "details", "logo", "logos", "cart", "count", "date", "dates",
        "main", "home", "index", "view", "views", "list", "lists", "show", "item", "items",
        "product", "products", "order", "orders", "blog", "news", "post", "posts",
        "page", "pages", "help", "info", "about", "contact", "terms", "privacy",
        "docs", "doc", "api", "user", "users", "group", "groups", "file", "files",
        "media", "image", "images", "img", "static", "assets", "css", "js", "fonts",
        "app", "download", "downloads", "search", "find", "share", "tag", "tags",
        "category", "categories", "forum", "event", "events", "form", "forms",
        "report", "reports", "status", "feed", "feeds", "site", "sites", "link", "links",
        "pricing", "plan", "plans", "price", "store", "stores", "shop", "shopping",
        "guide", "guides", "tutorial", "tutorials", "code", "tools", "utility",
        "release", "releases", "version", "general", "public", "common", "global",
        "activity", "activities", "action", "actions", "dashboard", "portal", "profile", "session", "day"
    )

    // Cyrillic and Greek homoglyphs commonly used in URL obfuscation
    private val HOMOGLYPH_MAP = mapOf(
        'а' to 'a', 'е' to 'e', 'і' to 'i', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'у' to 'y', 'х' to 'x',
        'ӏ' to 'l', 'α' to 'a', 'ο' to 'o', 'ν' to 'v', 'ѕ' to 's', 'ԁ' to 'd', 'ԝ' to 'w',
        'А' to 'A', 'В' to 'B', 'Е' to 'E', 'К' to 'K', 'М' to 'M', 'Н' to 'H', 'О' to 'O', 'Р' to 'P',
        'С' to 'C', 'Т' to 'T', 'Х' to 'X'
    )

    fun analyze(
        path: String,
        query: String,
        host: String,
        isKnownLegitimateDomain: Boolean
    ): PathAnalysisResult {
        val cleanHost = host.lowercase().trim()
        val rootDomain = DomainUtils.extractRootDomain(cleanHost)

        // Find domain expected paths profile if available
        val profileKey = DOMAIN_EXPECTED_PATHS.keys.firstOrNull {
            cleanHost == it || cleanHost.endsWith(".$it") || rootDomain == it
        }
        val expectedPaths = profileKey?.let { DOMAIN_EXPECTED_PATHS[it] } ?: emptySet()
        val isKnownProfileDomain = profileKey != null

        val rawPathSegments = path.split('/', '\\')
            .map { it.trim() }
            .filter { it.isNotBlank() }

        val anomalies = mutableListOf<PathSegmentAnomaly>()
        val threats = mutableListOf<String>()

        var isExpectedProfilePath = false
        var expectedProfileMatched: String? = null
        var hasSensitiveTermAnomaly = false
        var hasNumericSubstitution = false
        var hasSuspiciousCapitalization = false
        var hasEncodedPathChars = path.contains("%") || path.contains("+")

        // 1. Analyze each path segment
        for ((idx, segment) in rawPathSegments.withIndex()) {
            val stripped = segment.substringBefore('?').substringBefore('#')
            val withoutExt = if (stripped.contains('.')) stripped.substringBeforeLast('.') else stripped
            val lower = withoutExt.lowercase()

            if (lower.isBlank() || lower.length > 50) continue

            // Check if this segment matches an expected profile path exactly
            if (isKnownProfileDomain && expectedPaths.contains(lower)) {
                isExpectedProfilePath = true
                expectedProfileMatched = lower
                continue
            }

            // Check if this segment is a standard benign dictionary/web word
            if (BENIGN_PATH_WORDS.contains(lower)) {
                continue
            }

            // Check if segment is an exact match to a sensitive term (e.g. /login on example.com)
            // Exact match to standard keyword is normal expected structure -> NOT an anomaly!
            if (SENSITIVE_PATH_TERMS.contains(lower)) {
                continue
            }

            // Check Case-Sensitive Lookalike: Uppercase 'I' visually substituting for lowercase 'l'
            if (withoutExt.contains('I') && withoutExt.any { it.isLowerCase() }) {
                val visualMapped = withoutExt.replace('I', 'l').lowercase()
                val target = (expectedPaths + SENSITIVE_PATH_TERMS).firstOrNull { it == visualMapped }
                if (target != null) {
                    val anom = PathSegmentAnomaly(
                        rawSegment = withoutExt,
                        targetKeyword = target,
                        anomalyType = "VisualLookalike",
                        description = "Path segment '$withoutExt' visually imitates '$target' using uppercase 'I' to mimic lowercase 'l'",
                        distance = 1,
                        severity = if (isSensitive(target)) "High" else "Medium"
                    )
                    anomalies.add(anom)
                    threats.add(anom.description)
                    hasSuspiciousCapitalization = true
                    continue
                }
            }

            // Check Homoglyphs
            if (withoutExt.any { HOMOGLYPH_MAP.containsKey(it) }) {
                val deHomoglyph = buildString {
                    for (c in withoutExt) {
                        append(HOMOGLYPH_MAP[c] ?: c)
                    }
                }.lowercase()
                val target = (expectedPaths + SENSITIVE_PATH_TERMS).firstOrNull { it == deHomoglyph }
                if (target != null) {
                    val anom = PathSegmentAnomaly(
                        rawSegment = withoutExt,
                        targetKeyword = target,
                        anomalyType = "Homoglyph",
                        description = "Unicode homoglyph character mixing in path: '$withoutExt' spoofs '$target'",
                        distance = 1,
                        severity = "High"
                    )
                    anomalies.add(anom)
                    threats.add(anom.description)
                    continue
                }
            }

            // Check Numeric / Leetspeak Substitutions (e.g. l0gin, acc0unt, r3el)
            if (lower.any { it.isDigit() || it == '@' || it == '$' || it == '!' }) {
                val leetTarget = checkLeetSubstitution(lower, expectedPaths + SENSITIVE_PATH_TERMS)
                if (leetTarget != null) {
                    val anom = PathSegmentAnomaly(
                        rawSegment = withoutExt,
                        targetKeyword = leetTarget,
                        anomalyType = "DigitSubstitution",
                        description = "Deceptive character substitution / leetspeak in path ('$withoutExt' spoofing '$leetTarget')",
                        distance = 1,
                        severity = if (isSensitive(leetTarget)) "High" else "Medium"
                    )
                    anomalies.add(anom)
                    threats.add(anom.description)
                    hasNumericSubstitution = true
                    if (isSensitive(leetTarget)) hasSensitiveTermAnomaly = true
                    continue
                }
            }

            // Check against Expected Paths of Known Domain Profile (e.g. reeel on instagram.com)
            if (isKnownProfileDomain && idx <= 2) {
                val match = checkTypoAgainstSet(lower, expectedPaths)
                if (match != null) {
                    val anom = PathSegmentAnomaly(
                        rawSegment = withoutExt,
                        targetKeyword = match.target,
                        anomalyType = match.type,
                        description = "Path differs from common '/${match.target}/' structure: path token '$withoutExt' is highly similar to '${match.target}' (${match.detail})",
                        distance = match.distance,
                        severity = "Medium"
                    )
                    anomalies.add(anom)
                    threats.add(anom.description)
                    continue
                }
            }

            // Check against Sensitive Terms across ALL domains (e.g. retial vs retail, bnak vs bank)
            val sensitiveMatch = checkTypoAgainstSet(lower, SENSITIVE_PATH_TERMS.toSet())
            if (sensitiveMatch != null) {
                val anom = PathSegmentAnomaly(
                    rawSegment = withoutExt,
                    targetKeyword = sensitiveMatch.target,
                    anomalyType = sensitiveMatch.type,
                    description = "Suspicious path typo detected: segment '$withoutExt' appears to imitate '${sensitiveMatch.target}' (${sensitiveMatch.detail})",
                    distance = sensitiveMatch.distance,
                    severity = "High"
                )
                anomalies.add(anom)
                threats.add(anom.description)
                hasSensitiveTermAnomaly = true
                continue
            }
        }

        // 2. Query Parameter Analysis
        val queryAnalysis = analyzeQueryParameters(query, cleanHost)
        if (queryAnalysis.detectedIssues.isNotEmpty()) {
            threats.addAll(queryAnalysis.detectedIssues)
        }

        // 3. Compute Path Anomaly Score
        var score = 0
        if (anomalies.isNotEmpty()) {
            for (anom in anomalies) {
                score += when (anom.severity) {
                    "Critical" -> 60
                    "High" -> 45
                    "Medium" -> 35
                    else -> 20
                }
            }
        }

        if (queryAnalysis.hasSuspiciousRedirect) score += 40
        if (queryAnalysis.hasJsPayload) score += 60
        if (queryAnalysis.hasNestedUrl && !queryAnalysis.isBenignTrackingOrSessionToken) score += 25

        score = score.coerceIn(0, 100)
        val hasPathAnomaly = anomalies.isNotEmpty() || queryAnalysis.hasSuspiciousRedirect || queryAnalysis.hasJsPayload

        val explanation = buildString {
            if (anomalies.isNotEmpty()) {
                val descList = anomalies.map { it.description }
                append(descList.joinToString(". "))
                append(". ")
            }
            if (queryAnalysis.detectedIssues.isNotEmpty()) {
                append(queryAnalysis.detectedIssues.joinToString(". "))
                append(". ")
            }
            if (queryAnalysis.isBenignTrackingOrSessionToken) {
                append("Query contains encoded session/state parameter without redirection. ")
            }
        }.trim()

        return PathAnalysisResult(
            hasPathAnomaly = hasPathAnomaly,
            pathAnomalyScore = score,
            anomalies = anomalies,
            expectedProfileMatched = expectedProfileMatched,
            isKnownProfileDomain = isKnownProfileDomain,
            isExpectedProfilePath = isExpectedProfilePath,
            hasSensitiveTermAnomaly = hasSensitiveTermAnomaly,
            hasNumericSubstitution = hasNumericSubstitution,
            hasSuspiciousCapitalization = hasSuspiciousCapitalization,
            hasEncodedPathChars = hasEncodedPathChars,
            pathSegmentCount = rawPathSegments.size,
            suspiciousPathTokensCount = anomalies.size,
            queryAnalysis = queryAnalysis,
            detectedThreats = threats.distinct(),
            explanation = explanation
        )
    }

    private fun isSensitive(term: String): Boolean {
        return SENSITIVE_PATH_TERMS.contains(term.lowercase())
    }

    private data class TypoCheckResult(
        val target: String,
        val type: String,
        val distance: Int,
        val detail: String
    )

    private fun checkTypoAgainstSet(candidate: String, targets: Set<String>): TypoCheckResult? {
        val candLen = candidate.length
        if (candLen < 3 || candLen > 25) return null

        for (target in targets) {
            val targLen = target.length
            if (candidate == target) continue

            // 1. Adjacent character transposition (e.g. retial vs retail)
            if (candLen == targLen && candLen >= 4 && isAdjacentTransposition(candidate, target)) {
                return TypoCheckResult(
                    target = target,
                    type = "Transposition",
                    distance = 1,
                    detail = "characters transposed"
                )
            }

            // 2. Repeated character manipulation / stuttering (e.g. reeel vs reel)
            if (candLen > targLen && isRepeatedCharacter(candidate, target)) {
                return TypoCheckResult(
                    target = target,
                    type = "RepeatedCharacter",
                    distance = candLen - targLen,
                    detail = "repeated character insertion"
                )
            }

            // 3. Single character insertion (e.g. reeel vs reel, candLen == targLen + 1)
            if (candLen == targLen + 1 && isSingleCharInsertion(candidate, target)) {
                return TypoCheckResult(
                    target = target,
                    type = "CharacterInsertion",
                    distance = 1,
                    detail = "single character insertion"
                )
            }

            // 4. Single character omission (e.g. acount vs account)
            if (candLen + 1 == targLen && targLen >= 5 && isSingleCharInsertion(target, candidate)) {
                return TypoCheckResult(
                    target = target,
                    type = "CharacterDeletion",
                    distance = 1,
                    detail = "single character omission"
                )
            }

            // 5. Single character substitution (e.g. logen vs login)
            if (candLen == targLen && targLen >= 4 && isSingleCharSubstitution(candidate, target)) {
                // Ensure the candidate is not a valid benign word
                if (!BENIGN_PATH_WORDS.contains(candidate)) {
                    return TypoCheckResult(
                        target = target,
                        type = "CharacterSubstitution",
                        distance = 1,
                        detail = "single character substitution"
                    )
                }
            }

            // 6. General Damerau-Levenshtein distance = 1 for targets of length >= 4
            if (targLen >= 4 && abs(candLen - targLen) <= 1) {
                val dist = damerauLevenshteinDistance(candidate, target)
                if (dist == 1 && !BENIGN_PATH_WORDS.contains(candidate)) {
                    return TypoCheckResult(
                        target = target,
                        type = "CharacterSubstitution",
                        distance = 1,
                        detail = "Damerau-Levenshtein distance 1"
                    )
                }
            }
        }
        return null
    }

    private fun checkLeetSubstitution(candidate: String, targets: Iterable<String>): String? {
        val deLeetedI = candidate
            .replace('0', 'o')
            .replace('1', 'i')
            .replace('3', 'e')
            .replace('4', 'a')
            .replace('5', 's')
            .replace('7', 't')
            .replace('8', 'b')
            .replace('@', 'a')
            .replace('$', 's')
            .replace('!', 'i')

        val deLeetedL = candidate
            .replace('0', 'o')
            .replace('1', 'l')
            .replace('3', 'e')
            .replace('4', 'a')
            .replace('5', 's')
            .replace('7', 't')
            .replace('8', 'b')
            .replace('@', 'a')
            .replace('$', 's')
            .replace('!', 'l')

        for (target in targets) {
            val tLower = target.lowercase()
            if ((deLeetedI == tLower || deLeetedL == tLower) && candidate != tLower) {
                return target
            }
        }
        return null
    }

    fun analyzeQueryParameters(query: String, host: String): QueryAnalysisResult {
        if (query.isBlank()) {
            return QueryAnalysisResult()
        }

        var hasExcessiveEncoding = false
        var hasSuspiciousRedirect = false
        var hasExternalUrl = false
        var hasJsPayload = false
        var hasSuspiciousParamName = false
        var hasExtremelyLongValue = false
        var hasEncodedDomain = false
        var hasNestedUrl = false
        var isBenignTrackingOrSessionToken = false
        val issues = mutableListOf<String>()

        val params = query.split('&', ';').map { it.trim() }.filter { it.isNotBlank() }
        val rootDomain = DomainUtils.extractRootDomain(host)

        val redirectParamNames = setOf(
            "url", "redirect", "redirect_to", "redirect_url", "dest", "destination",
            "next", "target", "return", "return_to", "continue", "goto", "out",
            "forward", "callback", "link"
        )

        for (param in params) {
            val key = param.substringBefore('=').lowercase().trim()
            val rawValue = if (param.contains('=')) param.substringAfter('=') else ""

            if (rawValue.length > 1000) {
                hasExtremelyLongValue = true
                issues.add("Extremely long query parameter value (${rawValue.length} chars)")
            }

            // Check for double percent-encoding
            if (rawValue.contains("%25", ignoreCase = true)) {
                hasExcessiveEncoding = true
                issues.add("Double URL percent-encoding in query parameter '$key'")
            }

            val decodedValue = try {
                URLDecoder.decode(rawValue, "UTF-8")
            } catch (e: Exception) {
                rawValue
            }

            // Check for JavaScript payloads
            val lowerDecoded = decodedValue.lowercase()
            if (lowerDecoded.contains("<script") || lowerDecoded.contains("javascript:") ||
                lowerDecoded.contains("alert(") || lowerDecoded.contains("document.cookie") ||
                lowerDecoded.contains("onload=") || lowerDecoded.contains("onerror=")
            ) {
                hasJsPayload = true
                issues.add("Potential cross-site script payload detected in parameter '$key'")
            }

            // Check for nested URLs or redirect parameters
            val isNested = lowerDecoded.startsWith("http://") || lowerDecoded.startsWith("https://") || lowerDecoded.startsWith("//")
            if (isNested) {
                hasNestedUrl = true
                val targetHost = try {
                    val clean = if (decodedValue.startsWith("//")) "https:$decodedValue" else decodedValue
                    java.net.URI(clean).host?.lowercase() ?: ""
                } catch (e: Exception) {
                    ""
                }

                val targetRoot = if (targetHost.isNotBlank()) DomainUtils.extractRootDomain(targetHost) else ""
                val isExternal = targetRoot.isNotBlank() && rootDomain.isNotBlank() && targetRoot != rootDomain

                if (isExternal) {
                    hasExternalUrl = true
                    if (redirectParamNames.contains(key)) {
                        hasSuspiciousRedirect = true
                        issues.add("Potential Open Redirect: parameter '$key' routes to external domain '$targetHost'")
                    }
                }
            }

            // Check for legitimate Base64 tracking / session token (e.g. ?stkn=ZjFkYzMzMDQzZg==)
            if (isBase64Candidate(rawValue)) {
                // Legitimate tracking, CSRF, or authentication token
                if (!hasJsPayload && !hasSuspiciousRedirect) {
                    isBenignTrackingOrSessionToken = true
                }
            }
        }

        val complexityScore = (params.size * 0.1f +
                (if (hasNestedUrl) 0.4f else 0.0f) +
                (if (hasExcessiveEncoding) 0.3f else 0.0f) +
                (if (hasExtremelyLongValue) 0.3f else 0.0f)).coerceIn(0.0f, 1.0f)

        return QueryAnalysisResult(
            hasExcessiveEncoding = hasExcessiveEncoding,
            hasSuspiciousRedirect = hasSuspiciousRedirect,
            hasExternalUrl = hasExternalUrl,
            hasJsPayload = hasJsPayload,
            hasSuspiciousParamName = hasSuspiciousParamName,
            hasExtremelyLongValue = hasExtremelyLongValue,
            hasEncodedDomain = hasEncodedDomain,
            hasNestedUrl = hasNestedUrl,
            isBenignTrackingOrSessionToken = isBenignTrackingOrSessionToken,
            detectedIssues = issues,
            queryComplexityScore = complexityScore
        )
    }

    private fun isBase64Candidate(str: String): Boolean {
        if (str.length < 8 || str.length > 512) return false
        val clean = str.trimEnd('=')
        if (clean.length % 4 !in listOf(0, 2, 3)) return false
        return clean.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '-' || it == '_' }
    }

    private fun isAdjacentTransposition(s1: String, s2: String): Boolean {
        if (s1.length != s2.length || s1 == s2) return false
        val diffIndices = mutableListOf<Int>()
        for (i in s1.indices) {
            if (s1[i] != s2[i]) diffIndices.add(i)
        }
        return diffIndices.size == 2 &&
                diffIndices[1] == diffIndices[0] + 1 &&
                s1[diffIndices[0]] == s2[diffIndices[1]] &&
                s1[diffIndices[1]] == s2[diffIndices[0]]
    }

    private fun isSingleCharInsertion(longer: String, shorter: String): Boolean {
        if (longer.length != shorter.length + 1) return false
        var diffFound = false
        var i = 0
        var j = 0
        while (i < longer.length && j < shorter.length) {
            if (longer[i] != shorter[j]) {
                if (diffFound) return false
                diffFound = true
                i++
            } else {
                i++
                j++
            }
        }
        return true
    }

    private fun isSingleCharSubstitution(s1: String, s2: String): Boolean {
        if (s1.length != s2.length || s1 == s2) return false
        var diffCount = 0
        for (i in s1.indices) {
            if (s1[i] != s2[i]) {
                diffCount++
                if (diffCount > 1) return false
            }
        }
        return diffCount == 1
    }

    private fun isRepeatedCharacter(longer: String, base: String): Boolean {
        if (longer.length <= base.length) return false
        fun collapse(s: String): String {
            val sb = StringBuilder()
            for (i in s.indices) {
                if (i == 0 || s[i] != s[i - 1]) sb.append(s[i])
            }
            return sb.toString()
        }
        val c1 = collapse(longer)
        val c2 = collapse(base)
        return c1 == c2
    }

    fun damerauLevenshteinDistance(s1: String, s2: String): Int {
        val len1 = s1.length
        val len2 = s2.length
        val d = Array(len1 + 1) { IntArray(len2 + 1) }

        for (i in 0..len1) d[i][0] = i
        for (j in 0..len2) d[0][j] = j

        for (i in 1..len1) {
            for (j in 1..len2) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                d[i][j] = minOf(
                    d[i - 1][j] + 1,        // deletion
                    d[i][j - 1] + 1,        // insertion
                    d[i - 1][j - 1] + cost  // substitution
                )
                if (i > 1 && j > 1 && s1[i - 1] == s2[j - 2] && s1[i - 2] == s2[j - 1]) {
                    d[i][j] = minOf(d[i][j], d[i - 2][j - 2] + 1) // transposition
                }
            }
        }
        return d[len1][len2]
    }

    private val SENSITIVE_PARAM_KEYS = setOf(
        "session_id", "sessionid", "session", "sess_id", "sess", "jsessionid", "phpsessid", "aspsessionid",
        "token", "access_token", "auth_token", "authtoken", "id_token", "refresh_token", "bearer",
        "day_id", "dayid", "api_key", "apikey", "secret", "client_secret",
        "password", "pass", "pwd", "otp", "code", "pin", "auth", "state", "nonce"
    )

    private val SENSITIVE_TOKEN_VALUE_REGEX = Regex("""^[0-9a-fA-F]{16,}$|^[0-9a-zA-Z_-]{20,}$""")

    /**
     * Strips or redacts sensitive authentication parameters (e.g. session_id, day_id, access_token,
     * long hex/alphanumeric tokens) before sending queries to external AI/RAG or external services.
     */
    fun redactSensitiveQueryParams(query: String): String {
        if (query.isBlank()) return ""
        val pairs = query.split('&', ';').filter { it.isNotBlank() }
        val redactedPairs = pairs.map { pair ->
            val idx = pair.indexOf('=')
            if (idx == -1) {
                pair
            } else {
                val key = pair.substring(0, idx).trim()
                val value = pair.substring(idx + 1).trim()
                val keyLower = key.lowercase()
                val isSensitiveKey = SENSITIVE_PARAM_KEYS.contains(keyLower) ||
                        keyLower.endsWith("token") || keyLower.endsWith("session") ||
                        keyLower.endsWith("secret") || keyLower.endsWith("password")
                val isSensitiveValue = value.length >= 16 && SENSITIVE_TOKEN_VALUE_REGEX.matches(value)

                if (isSensitiveKey || isSensitiveValue) {
                    "$key=[REDACTED]"
                } else {
                    pair
                }
            }
        }
        return redactedPairs.joinToString("&")
    }
}
