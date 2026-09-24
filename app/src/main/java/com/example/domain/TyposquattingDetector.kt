package com.example.domain

import kotlin.math.abs

data class TyposquatMatch(
    val candidate: String,
    val targetKeyword: String,
    val matchType: String, // "VisualLookalike", "Transposition", "CharacterSubstitution", "CharacterOmission", "CharacterInsertion", "DigitSubstitution", "Homoglyph", "RepeatedCharacter"
    val description: String,
    val confidence: Float
)

/**
 * Generalized, high-performance engine for detecting typosquatting, lookalikes,
 * character transpositions, homoglyphs, visual confusions, and leetspeak across
 * hostnames, subdomains, and URL path tokens.
 */
object TyposquattingDetector {

    // High-value sensitive service & authentication keywords
    val SENSITIVE_KEYWORDS = listOf(
        "retail", "corporate", "netbanking", "banking", "personal", "bank",
        "login", "signin", "sign-in", "signon", "auth", "authenticate",
        "account", "accounts", "portal", "secure", "security",
        "verify", "verification", "payment", "payments", "dashboard",
        "admin", "support", "update", "wallet", "kyc", "password",
        "online", "service", "services", "official", "customer",
        "reel", "reels", "stories", "checkout"
    )

    // High-value brand names
    val HIGH_VALUE_BRANDS = listOf(
        "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank",
        "pnb", "axis", "axisbank", "kotak", "bankofbaroda", "canarabank",
        "indusind", "unionbank", "idbi", "yesbank",
        "paypal", "google", "microsoft", "apple", "amazon", "netflix",
        "facebook", "instagram", "whatsapp", "binance", "coinbase", "meta", "twitter"
    )

    // Unicode homoglyph map
    private val HOMOGLYPH_MAP = mapOf(
        'а' to 'a', 'е' to 'e', 'і' to 'i', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'у' to 'y', 'х' to 'x',
        'ӏ' to 'l', 'α' to 'a', 'ο' to 'o', 'ν' to 'v', 'ѕ' to 's', 'ԁ' to 'd', 'ԛ' to 'q', 'ԝ' to 'w',
        'А' to 'A', 'В' to 'B', 'Е' to 'E', 'К' to 'K', 'М' to 'M', 'Н' to 'H', 'О' to 'O', 'Р' to 'P',
        'С' to 'C', 'Т' to 'T', 'Х' to 'X', 'Ү' to 'Y', 'ɑ' to 'a', 'ɡ' to 'g', 'ɩ' to 'i'
    )

    // Benign dictionary/common web words to avoid false positives
    val BENIGN_WORDS = setOf(
        "detail", "details", "logo", "cart", "count", "date", "blog", "news", "article", "post",
        "forum", "help", "contact", "about", "terms", "privacy", "legal", "home", "index", "main",
        "default", "search", "view", "show", "list", "item", "page", "site", "static", "assets",
        "images", "css", "js", "scripts", "media", "download", "product", "products", "category",
        "shop", "store", "order", "status", "event", "events", "press", "careers", "jobs",
        "investors", "developer", "developers", "docs", "api", "feed", "tag", "tags", "archive",
        "user", "users", "profile", "comment", "comments", "feedback", "faq", "pricing", "plan",
        "plans", "billing", "invoice", "receipt", "ticket", "tickets", "booking", "travel", "hotel",
        "flights", "train", "bus", "movie", "music", "video", "videos", "photo", "photos", "audio",
        "podcast", "stream", "play", "game", "games", "quiz", "survey", "report", "analytics",
        "metrics", "logs", "config", "settings", "theme", "lang", "locale", "translate", "share",
        "social", "follow", "subscribe", "rss", "mail", "email", "chat", "message", "messages",
        "inbox", "notifications", "alerts", "reminders", "calendar", "tasks", "notes", "files",
        "drive", "cloud", "storage", "backup", "sync", "device", "devices", "app", "apps",
        "mobile", "web", "desktop", "plugin", "plugins", "extension", "addons", "tools", "utility",
        "utilities", "guide", "guides", "tutorial", "manual", "handbook", "specs", "release",
        "releases", "version", "changelog", "roadmap", "statuspage", "health", "ping", "test",
        "demo", "sample", "example", "preview", "beta", "alpha", "staging", "prod", "production",
        "live", "intl", "global", "corp", "enterprise", "partner", "partners", "vendor",
        "affiliate", "reseller", "community", "network", "group", "team", "members", "directory",
        "staff", "board", "leadership", "governance", "compliance", "audit", "securitytxt", "robots", "sitemap"
    )

    fun isAdjacentTransposition(s1: String, s2: String): Boolean {
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

    fun isSingleCharInsertion(longer: String, shorter: String): Boolean {
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

    fun isSingleCharDeletion(shorter: String, longer: String): Boolean {
        return isSingleCharInsertion(longer, shorter)
    }

    fun isSingleCharSubstitution(s1: String, s2: String): Boolean {
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

    fun isRepeatedCharManipulation(s1: String, s2: String): Boolean {
        if (s1 == s2 || s1.length <= s2.length) return false
        fun collapse(s: String): String {
            val sb = StringBuilder()
            for (i in s.indices) {
                if (i == 0 || s[i] != s[i - 1]) sb.append(s[i])
            }
            return sb.toString()
        }
        val collapsed1 = collapse(s1)
        val collapsed2 = collapse(s2)
        if (collapsed1 == collapsed2) {
            val hasTriple = (0 until s1.length - 2).any { s1[it] == s1[it + 1] && s1[it] == s1[it + 2] }
            if (hasTriple) return true
            if (s1.length >= s2.length + 2) return true
        }
        return false
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

    /**
     * Checks if a candidate token matches any high-value keyword or brand as a typosquat or lookalike.
     * Returns a [TyposquatMatch] if a suspicious manipulation is detected, or null if legitimate/benign.
     */
    fun detect(rawToken: String, additionalTargets: List<String> = emptyList()): TyposquatMatch? {
        val token = rawToken.trim()
        if (token.length < 3 || token.length > 35) return null

        val lower = token.lowercase()
        val canon = lower.replace("-", "").replace("_", "")

        val allTargets = (SENSITIVE_KEYWORDS + HIGH_VALUE_BRANDS + additionalTargets).distinct()
        val cleanKeywordSet = allTargets.map { it.lowercase() }.toSet()
        val canonicalKeywordMap = allTargets.associateWith {
            it.lowercase().replace("-", "").replace("_", "")
        }

        // 1. Exact match to a legitimate keyword -> NOT a typosquat/lookalike
        if (cleanKeywordSet.contains(lower) || canonicalKeywordMap.values.contains(canon)) {
            return null
        }

        // 2. Benign web/dictionary words -> NOT a typosquat
        if (BENIGN_WORDS.contains(lower) || BENIGN_WORDS.contains(canon)) {
            return null
        }

        // 3. Case-sensitive lookalike: Uppercase 'I' visually substituting for lowercase 'l' (e.g. 'retaiI')
        if (token.contains('I') && token.any { it.isLowerCase() }) {
            val visualMapped = token.replace('I', 'l').lowercase()
            if (visualMapped != lower) {
                for (keyword in allTargets) {
                    val cKey = canonicalKeywordMap[keyword] ?: keyword
                    if (visualMapped == keyword.lowercase() || visualMapped.replace("-", "").replace("_", "") == cKey) {
                        return TyposquatMatch(
                            candidate = token,
                            targetKeyword = keyword,
                            matchType = "VisualLookalike",
                            description = "Suspicious case-sensitive lookalike: '$token' visually imitates '$keyword' (uppercase 'I' for 'l')",
                            confidence = 0.98f
                        )
                    }
                }
            }
        }

        // 4. Unicode homoglyphs
        if (token.any { HOMOGLYPH_MAP.containsKey(it) }) {
            val deHomoglyph = buildString {
                for (c in token) {
                    append(HOMOGLYPH_MAP[c] ?: c)
                }
            }.lowercase()
            for (keyword in allTargets) {
                val cKey = canonicalKeywordMap[keyword] ?: keyword
                if (deHomoglyph == keyword.lowercase() || deHomoglyph.replace("-", "").replace("_", "") == cKey) {
                    return TyposquatMatch(
                        candidate = token,
                        targetKeyword = keyword,
                        matchType = "Homoglyph",
                        description = "Unicode homoglyph character mixing: '$token' spoofs '$keyword'",
                        confidence = 0.98f
                    )
                }
            }
        }

        // 5. Digit substitutions (Leetspeak: '1' for 'l'/'i', '0' for 'o', etc.)
        if (lower.any { it.isDigit() || it == '@' || it == '$' }) {
            val deDigitL = lower
                .replace('1', 'l')
                .replace('0', 'o')
                .replace('3', 'e')
                .replace('4', 'a')
                .replace('5', 's')
                .replace('7', 't')
                .replace('8', 'b')
                .replace('@', 'a')
                .replace('$', 's')

            val deDigitI = lower
                .replace('1', 'i')
                .replace('0', 'o')
                .replace('3', 'e')
                .replace('4', 'a')
                .replace('5', 's')
                .replace('7', 't')
                .replace('8', 'b')
                .replace('@', 'a')
                .replace('$', 's')

            for (keyword in allTargets) {
                val cKey = canonicalKeywordMap[keyword] ?: keyword
                if ((deDigitL == keyword.lowercase() || deDigitI == keyword.lowercase() ||
                     deDigitL.replace("-", "").replace("_", "") == cKey ||
                     deDigitI.replace("-", "").replace("_", "") == cKey) &&
                    !lower.contains(keyword.lowercase())
                ) {
                    return TyposquatMatch(
                        candidate = token,
                        targetKeyword = keyword,
                        matchType = "DigitSubstitution",
                        description = "Suspicious digit substitution / leetspeak: '$token' imitates '$keyword'",
                        confidence = 0.95f
                    )
                }
            }
        }

        // 6. Visual character substitutions:
        // 'i' <-> 'l' (e.g. 'retaii' -> 'retail', 'paypai' -> 'paypal')
        // 'ii' <-> 'il'
        // 'll' <-> 'il'
        // 'vv' <-> 'w'
        // 'rn' <-> 'm'
        val visualNormalizedLtoI = lower.replace('l', 'i')
        val visualNormalizedItoL = lower.replace('i', 'l')

        for (keyword in allTargets) {
            val cKey = canonicalKeywordMap[keyword] ?: keyword
            val kwLower = keyword.lowercase()
            val kwLtoI = kwLower.replace('l', 'i')
            val kwItoL = kwLower.replace('i', 'l')

            if (kwLower.length >= 4 && (lower != kwLower)) {
                // Check if substituting visual pairs makes them identical
                if (visualNormalizedLtoI == kwLtoI || visualNormalizedItoL == kwItoL) {
                    return TyposquatMatch(
                        candidate = token,
                        targetKeyword = keyword,
                        matchType = "VisualLookalike",
                        description = "Suspicious visual lookalike: '$token' imitates '$keyword' (visual confusion between 'i' and 'l')",
                        confidence = 0.95f
                    )
                }

                // Check 'rn' <-> 'm'
                if (lower.replace("rn", "m") == kwLower || lower == kwLower.replace("m", "rn")) {
                    return TyposquatMatch(
                        candidate = token,
                        targetKeyword = keyword,
                        matchType = "VisualLookalike",
                        description = "Suspicious visual character clustering: '$token' imitates '$keyword' ('rn' for 'm')",
                        confidence = 0.95f
                    )
                }

                // Check 'vv' <-> 'w'
                if (lower.replace("vv", "w") == kwLower || lower == kwLower.replace("w", "vv")) {
                    return TyposquatMatch(
                        candidate = token,
                        targetKeyword = keyword,
                        matchType = "VisualLookalike",
                        description = "Suspicious visual character clustering: '$token' imitates '$keyword' ('vv' for 'w')",
                        confidence = 0.95f
                    )
                }
            }
        }

        // 7. Structural Typos: Transposition, Stutter/Repeat, Edit Distance
        for (keyword in allTargets) {
            val cKey = canonicalKeywordMap[keyword] ?: keyword
            val kwLower = keyword.lowercase()

            // Check Adjacent Character Transposition (e.g. retial vs retail, logni vs login)
            if (canon.length == cKey.length && canon.length >= 4) {
                if (isAdjacentTransposition(canon, cKey)) {
                    return TyposquatMatch(
                        candidate = token,
                        targetKeyword = keyword,
                        matchType = "Transposition",
                        description = "Suspicious adjacent transposition typo: '$token' appears to imitate '$keyword' (swapped characters)",
                        confidence = 0.95f
                    )
                }
            }

            // Check Repeated Character Stutter (e.g. reeetail vs retail, logggin vs login)
            if (canon.length > cKey.length && isRepeatedCharManipulation(canon, cKey)) {
                return TyposquatMatch(
                    candidate = token,
                    targetKeyword = keyword,
                    matchType = "RepeatedCharacter",
                    description = "Suspicious repeated-character padding: '$token' appears to imitate '$keyword'",
                    confidence = 0.90f
                )
            }

            // Check Single Character Edit Distance (insertion, deletion, substitution)
            // Allow length >= 4 for non-benign words, protecting short tokens like 'reel' and 'bank'
            if (cKey.length >= 4 && abs(canon.length - cKey.length) <= 1 && !BENIGN_WORDS.contains(canon)) {
                val dist = damerauLevenshteinDistance(canon, cKey)
                if (dist == 1) {
                    val (mType, desc) = when {
                        isSingleCharInsertion(canon, cKey) -> {
                            "CharacterInsertion" to "Suspicious typo: '$token' imitates '$keyword' (single character insertion)"
                        }
                        isSingleCharDeletion(canon, cKey) -> {
                            "CharacterOmission" to "Suspicious typo: '$token' imitates '$keyword' (single character omission)"
                        }
                        isSingleCharSubstitution(canon, cKey) -> {
                            "CharacterSubstitution" to "Suspicious typo: '$token' imitates '$keyword' (single character substitution)"
                        }
                        else -> {
                            "CharacterSubstitution" to "Suspicious typo: '$token' is suspiciously similar to '$keyword'"
                        }
                    }
                    return TyposquatMatch(
                        candidate = token,
                        targetKeyword = keyword,
                        matchType = mType,
                        description = desc,
                        confidence = 0.90f
                    )
                }
            }
        }

        return null
    }
}
