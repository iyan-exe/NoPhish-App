package com.example.domain

import java.net.URI
import kotlin.math.log2

data class UrlStructureAnalysisResult(
    val cleanHost: String,
    val rootDomain: String,
    val scheme: String,
    val path: String,
    val query: String,
    val isHttps: Boolean,
    val isIpAddress: Boolean,
    val isKnownLegitimate: Boolean,
    val suspiciousTld: String?,
    val typoSquattedBrand: String?,
    val hasAtSymbolTrick: Boolean,
    val excessiveSubdomains: Boolean,
    val hasHyphenStuffing: Boolean,
    val isShortener: Boolean,
    val hasSuspiciousPort: Boolean,
    val hasPhishingKeywords: Boolean,
    val highEntropy: Boolean,
    val isPunycode: Boolean,
    val hasPathObfuscation: Boolean = false,
    val hasPathLookalike: Boolean = false,
    val hasOpenRedirect: Boolean = false,
    val hasSuspiciousPayload: Boolean = false,
    val detectedThreats: List<String>,
    val explanation: String
)

object UrlStructureAnalyzer {

    // Untrusted / high-abuse TLDs heavily correlated with phishing campaigns
    val HIGH_RISK_TLDS = setOf(
        "top", "xyz", "icu", "buzz", "tk", "ml", "ga", "cf", "gq",
        "work", "click", "download", "racing", "men", "club", "surf",
        "vip", "rest", "cam", "fit", "sbs", "cfd", "monster", "uno",
        "pw", "cc", "ws", "trade", "bid", "loan", "date", "review",
        "zip", "mov", "kim", "party", "science", "stream", "gdn",
        "mom", "lol", "quest", "cyou", "host", "link", "shop", "live",
        "site", "online"
    )

    // Known URL shorteners that conceal true destinations
    val URL_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy",
        "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at", "goo.gl",
        "v.gd", "clck.ru", "shortcm.li", "t.ly", "bl.ink"
    )

    // Keywords that indicate phishing attempts when stuffed into UNTRUSTED domain tokens
    private val PHISHING_DOMAIN_TOKENS = setOf(
        "login", "signin", "logon", "auth", "authenticate", "sso",
        "verify", "verification", "secure", "security", "update",
        "wallet", "kyc", "otp", "passcode", "password", "airdrop",
        "drainer", "redelivery", "account-alert", "unauthorized"
    )

    // Sensitive security words often targeted with leetspeak/character substitution in paths
    private val SENSITIVE_KEYWORDS = listOf(
        "login", "signin", "logon", "auth", "authenticate", "verify", "verification",
        "update", "security", "secure", "password", "passcode", "account", "wallet",
        "banking", "bank", "otp", "credit", "debit", "card", "admin", "kyc", "sbi",
        "claim", "refund", "invoice", "payment", "portal", "confirm", "validation",
        "retail", "personal", "corporate", "netbanking", "online", "support", "service",
        "services", "customer", "profile", "access", "authorize"
    )

    // Sensitive keywords targeted by case-sensitive visual lookalikes or homoglyphs in paths
    private val PATH_LOOKALIKE_KEYWORDS = listOf(
        "retail", "personal", "corporate", "netbanking", "online", "banking", "bank",
        "login", "signin", "logon", "auth", "authenticate", "verify", "verification",
        "update", "security", "secure", "password", "passcode", "account", "wallet",
        "otp", "credit", "debit", "card", "admin", "kyc", "sbi", "claim", "refund",
        "invoice", "payment", "portal", "confirm", "validation", "support", "service",
        "services", "customer", "profile", "access", "authorize", "official"
    )

    private val PATH_HOMOGLYPH_MAP = mapOf(
        '\u0430' to 'a', '\u0435' to 'e', '\u0456' to 'i', '\u043E' to 'o',
        '\u0440' to 'p', '\u0441' to 'c', '\u0443' to 'y', '\u0445' to 'x',
        '\u0410' to 'A', '\u0412' to 'B', '\u0415' to 'E', '\u041D' to 'H',
        '\u041E' to 'O', '\u0420' to 'P', '\u0421' to 'C', '\u0422' to 'T'
    )

    fun analyze(rawUrl: String): UrlStructureAnalysisResult {
        val trimmed = rawUrl.trim()
        val normalized = if (!trimmed.startsWith("http://", ignoreCase = true) && !trimmed.startsWith("https://", ignoreCase = true)) {
            "https://$trimmed"
        } else {
            trimmed
        }

        val threats = mutableListOf<String>()
        var host = ""
        var path = ""
        var query = ""
        var scheme = ""
        var isHttps = true
        var isIp = false
        var isKnownLegit = false
        var suspiciousTld: String? = null
        var typoSquattedBrand: String? = null
        var hasAtSymbol = false
        var excessiveSubdomains = false
        var hasHyphenStuffing = false
        var isShortener = false
        var hasSuspiciousPort = false
        var hasPhishingKw = false
        var highEntropy = false
        var isPunycode = false
        var hasPathObfuscation = false
        var hasPathLookalike = false
        var hasOpenRedirect = false
        var hasSuspiciousPayload = false

        try {
            val uri = URI(normalized)
            scheme = uri.scheme ?: "https"
            isHttps = scheme.equals("https", ignoreCase = true)
            host = (uri.host ?: "").lowercase().trim()
            path = uri.path ?: ""
            query = uri.query ?: ""

            if (host.isBlank()) {
                host = DomainUtils.extractCleanHost(normalized)
            }

            val rootDomain = DomainUtils.extractRootDomain(host)
            isKnownLegit = DomainUtils.isKnownTopLegitimateDomain(host)

            // 1. Check for '@' symbol redirection trick
            if (trimmed.contains("@")) {
                hasAtSymbol = true
                threats.add("Deceptive '@' userinfo credential redirection trick")
            }

            // 2. IP Address check (IPv4 and IPv6 literal)
            val ipRegex = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
            val isIpv6 = host.startsWith("[") && host.endsWith("]")
            if (ipRegex.matches(host) || isIpv6) {
                isIp = true
                threats.add("Raw numerical IP address host ($host) instead of legitimate domain")
            }

            // 3. Port check
            if (uri.port != -1 && uri.port != 80 && uri.port != 443 && uri.port != 8080) {
                hasSuspiciousPort = true
                threats.add("Non-standard network port (:${uri.port})")
            }

            // 4. URL Shortener check
            if (URL_SHORTENERS.contains(host)) {
                isShortener = true
                threats.add("URL Shortener ($host) hides true destination")
            }

            // 5. High-risk TLD check (Only on non-verified domains)
            val hostParts = host.split(".")
            if (hostParts.size >= 2 && !isKnownLegit) {
                val tld = hostParts.last().lowercase()
                if (HIGH_RISK_TLDS.contains(tld)) {
                    suspiciousTld = tld
                    threats.add("Abnormal high-risk Top-Level Domain (.$tld)")
                }
            }

            // 6. Subdomain nesting check (skip for legitimate cloud hostings/services)
            if (hostParts.size > 3 && !isIp && !isKnownLegit) {
                excessiveSubdomains = true
                threats.add("Excessive subdomain depth (${hostParts.size} levels)")
            }

            // 7. Punycode check
            if (host.contains("xn--") || host.any { it.code > 127 }) {
                isPunycode = true
                threats.add("Punycode / IDN Homograph characters detected")
            }

            // 8. Hyphen stuffing on untrusted domains (e.g. secure-login-bank.xyz)
            val hyphenCount = host.count { it == '-' }
            if (hyphenCount >= 2 && !isKnownLegit) {
                hasHyphenStuffing = true
                threats.add("Hyphen stuffing in domain ($hyphenCount hyphens)")
            }

            // 9. Phishing keyword tokens inside domain name (NOT inside path of legitimate domains)
            if (!isKnownLegit) {
                val domainTokens = DomainUtils.extractDomainTokens(host)
                val matchedTokens = domainTokens.filter { PHISHING_DOMAIN_TOKENS.contains(it) }
                if (matchedTokens.isNotEmpty()) {
                    hasPhishingKw = true
                    threats.add("Domain contains security phishing keywords: ${matchedTokens.joinToString(", ")}")
                }
            }

            // 10. Typo-squatting check on non-legitimate domains
            if (!isKnownLegit) {
                val brandCheck = BrandImpersonationDetector.evaluate(host, "", normalized)
                if (brandCheck.isImpersonating) {
                    typoSquattedBrand = brandCheck.impersonatedBrand
                    threats.add("Brand impersonation targeting '${brandCheck.impersonatedBrand}'")
                }
            }

            // 11. High entropy calculation (only on untrusted domains)
            if (!isKnownLegit && !isIp) {
                val mainPart = if (hostParts.size >= 2) hostParts[hostParts.size - 2] else host
                val entropy = calculateEntropy(mainPart)
                if (entropy > 3.8 && mainPart.length > 10) {
                    highEntropy = true
                    threats.add("High character randomness / DGA domain signature")
                }
            }

            // 12. Plain HTTP protocol (Only flag if on non-whitelisted domain or sensitive action)
            if (!isHttps && !isKnownLegit) {
                threats.add("Insecure unencrypted HTTP protocol")
            }

            // 13. Path-level Deceptive Leetspeak / Character Substitution Analysis (Applies to ALL domains including whitelisted)
            val pathObfuscations = detectPathObfuscation(path, query)
            if (pathObfuscations.isNotEmpty()) {
                hasPathObfuscation = true
                threats.addAll(pathObfuscations)
            }

            // 14. Suspicious Case-Sensitive Lookalike Path Manipulation (e.g. retaiI with uppercase 'I' spoofing retail)
            val pathLookalikes = detectPathLookalike(path, query)
            if (pathLookalikes.isNotEmpty()) {
                hasPathLookalike = true
                threats.addAll(pathLookalikes)
            }

            // 15. Open Redirect parameter detection (never blindly trusting initial host)
            val openRedirects = detectOpenRedirect(path, query, host)
            if (openRedirects.isNotEmpty()) {
                hasOpenRedirect = true
                threats.addAll(openRedirects)
            }

            // 16. Suspicious executable payload detection in path (.apk, .exe, etc.)
            val dangerousPayloads = detectDangerousPayload(path)
            if (dangerousPayloads.isNotEmpty()) {
                hasSuspiciousPayload = true
                threats.addAll(dangerousPayloads)
            }

            // 17. Directory traversal / Null byte injections
            val traversalThreats = detectPathTraversalOrNullByte(normalized)
            if (traversalThreats.isNotEmpty()) {
                threats.addAll(traversalThreats)
            }

            val explanation = buildString {
                if (hasPathObfuscation) {
                    append("CRITICAL: Deceptive path obfuscation/leetspeak detected in URL endpoint. ")
                }
                if (hasPathLookalike) {
                    append("WARNING: Suspicious case-sensitive lookalike path detected (e.g., visual character imitation). ")
                }
                if (hasOpenRedirect) {
                    append("WARNING: Potential open redirect destination found in URL query. ")
                }
                if (hasSuspiciousPayload) {
                    append("DANGER: Direct executable application payload (.apk / .exe) targeted in path. ")
                }
                if (isKnownLegit && threats.isEmpty()) {
                    append("Domain '$host' is a verified legitimate web entity with secure structural properties.")
                } else if (isKnownLegit && hasPathLookalike && !hasPathObfuscation && !hasOpenRedirect && !hasSuspiciousPayload) {
                    append("Domain '$host' is a verified legitimate web entity, but the URL path exhibits suspicious lookalike manipulation ('$path'). Exercise caution.")
                } else if (threats.isEmpty()) {
                    append("Domain '$host' has standard structure with no typical manipulation techniques detected.")
                } else {
                    append("URL '$host$path' exhibits ${threats.size} structural risk factors: ")
                    append(threats.joinToString("; "))
                    append(".")
                }
            }

            return UrlStructureAnalysisResult(
                cleanHost = host,
                rootDomain = rootDomain,
                scheme = scheme,
                path = path,
                query = query,
                isHttps = isHttps,
                isIpAddress = isIp,
                isKnownLegitimate = isKnownLegit,
                suspiciousTld = suspiciousTld,
                typoSquattedBrand = typoSquattedBrand,
                hasAtSymbolTrick = hasAtSymbol,
                excessiveSubdomains = excessiveSubdomains,
                hasHyphenStuffing = hasHyphenStuffing,
                isShortener = isShortener,
                hasSuspiciousPort = hasSuspiciousPort,
                hasPhishingKeywords = hasPhishingKw,
                highEntropy = highEntropy,
                isPunycode = isPunycode,
                hasPathObfuscation = hasPathObfuscation,
                hasPathLookalike = hasPathLookalike,
                hasOpenRedirect = hasOpenRedirect,
                hasSuspiciousPayload = hasSuspiciousPayload,
                detectedThreats = threats,
                explanation = explanation
            )

        } catch (e: Exception) {
            return UrlStructureAnalysisResult(
                cleanHost = host,
                rootDomain = host,
                scheme = "http",
                path = "",
                query = "",
                isHttps = false,
                isIpAddress = false,
                isKnownLegitimate = false,
                suspiciousTld = null,
                typoSquattedBrand = null,
                hasAtSymbolTrick = false,
                excessiveSubdomains = false,
                hasHyphenStuffing = false,
                isShortener = false,
                hasSuspiciousPort = false,
                hasPhishingKeywords = false,
                highEntropy = false,
                isPunycode = false,
                hasPathObfuscation = false,
                hasPathLookalike = false,
                hasOpenRedirect = false,
                hasSuspiciousPayload = false,
                detectedThreats = listOf("Malformed URL syntax"),
                explanation = "Malformed URL syntax could not be parsed."
            )
        }
    }

    private fun detectPathObfuscation(path: String, query: String): List<String> {
        val threats = mutableListOf<String>()
        val combined = "$path $query"
        if (combined.isBlank()) return threats

        // Extract segments delimited by standard path and query separators
        val segments = combined.split('/', '\\', '-', '_', '.', '~', ';', '&', '=', '%', '?', '+')
            .map { it.trim() }
            .filter { it.length in 3..25 }

        for (segment in segments) {
            val lower = segment.lowercase()
            // Check if segment contains digits or leet characters mixed in
            val hasLeetCharacters = lower.any { it.isDigit() || it == '@' || it == '$' || it == '!' }
            if (hasLeetCharacters) {
                val deLeetedI = lower
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

                val deLeetedL = lower
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

                for (keyword in SENSITIVE_KEYWORDS) {
                    if ((deLeetedI == keyword || deLeetedL == keyword ||
                         deLeetedI.startsWith("$keyword") || deLeetedL.startsWith("$keyword") ||
                         deLeetedI.endsWith("$keyword") || deLeetedL.endsWith("$keyword")) &&
                        !lower.contains(keyword)
                    ) {
                        threats.add("Deceptive character substitution / leetspeak in URL path ('$segment' spoofing '$keyword')")
                        break
                    }
                }
            }
        }
        return threats
    }

    private fun detectPathLookalike(path: String, query: String): List<String> {
        val threats = mutableListOf<String>()
        val combined = "$path $query"
        if (combined.isBlank()) return threats

        val segments = combined.split('/', '\\', '-', '_', '.', '~', ';', '&', '=', '%', '?', '+')
            .map { it.trim() }
            .filter { it.length in 3..25 }

        for (segment in segments) {
            // 1. Case-sensitive lookalike: Uppercase 'I' (ASCII 73) visually substituting for lowercase 'l' (ASCII 108)
            // Segment must be mixed-case (contains 'I' and at least one lowercase letter, not an ALL-CAPS acronym)
            if (segment.contains('I') && segment.any { it.isLowerCase() }) {
                val visualMapped = segment.replace('I', 'l').lowercase()
                val normalLower = segment.lowercase()
                if (visualMapped != normalLower) {
                    for (keyword in PATH_LOOKALIKE_KEYWORDS) {
                        if (visualMapped == keyword || visualMapped.startsWith(keyword) || visualMapped.endsWith(keyword)) {
                            if (!normalLower.contains(keyword)) {
                                threats.add("Suspicious case-sensitive lookalike path manipulation: segment '$segment' visually imitates '$keyword' (uppercase 'I' for 'l')")
                                break
                            }
                        }
                    }
                }
            }

            // 2. Unicode homoglyphs in path segment
            if (segment.any { PATH_HOMOGLYPH_MAP.containsKey(it) }) {
                val deHomoglyph = buildString {
                    for (c in segment) {
                        append(PATH_HOMOGLYPH_MAP[c] ?: c)
                    }
                }.lowercase()
                for (keyword in PATH_LOOKALIKE_KEYWORDS) {
                    if (deHomoglyph == keyword || deHomoglyph.startsWith(keyword) || deHomoglyph.endsWith(keyword)) {
                        threats.add("Unicode homoglyph character mixing in URL path segment ('$segment' spoofing '$keyword')")
                        break
                    }
                }
            }
        }
        return threats
    }

    private fun detectOpenRedirect(path: String, query: String, host: String): List<String> {
        val threats = mutableListOf<String>()
        val combined = "$path?$query"
        val redirectParamRegex = Regex("""(?i)(?:[?&/])(url|redirect|redirect_to|redirect_url|dest|destination|next|target|return|return_to|continue|goto|out|to|u|q|link|r|forward|callback)=((?:https?%3A%2F%2F|https?://|//)[^&\s]+)""")
        val match = redirectParamRegex.find(combined)
        if (match != null) {
            val paramName = match.groupValues[1]
            val rawTarget = match.groupValues[2]
            val decodedTarget = try {
                java.net.URLDecoder.decode(rawTarget, "UTF-8")
            } catch (e: Exception) {
                rawTarget
            }
            val targetHost = try {
                val normalizedTarget = if (decodedTarget.startsWith("//")) "https:$decodedTarget" else decodedTarget
                URI(normalizedTarget).host?.lowercase() ?: ""
            } catch (e: Exception) {
                ""
            }

            val currentRootDomain = DomainUtils.extractRootDomain(host)
            val targetRootDomain = if (targetHost.isNotBlank()) DomainUtils.extractRootDomain(targetHost) else ""

            val isExternalRedirect = if (targetHost.isNotBlank() && currentRootDomain.isNotBlank()) {
                targetRootDomain != currentRootDomain
            } else {
                true
            }

            if (isExternalRedirect) {
                if (targetHost.isNotBlank()) {
                    threats.add("Potential Open Redirect on '$host': parameter '$paramName' routes to external target '$targetHost'")
                } else {
                    threats.add("Potential Open Redirect parameter '$paramName' pointing to external target ('${decodedTarget.take(35)}')")
                }
            }
        }
        return threats
    }

    private fun detectDangerousPayload(path: String): List<String> {
        val threats = mutableListOf<String>()
        val cleanPath = path.lowercase().substringBefore('?').substringBefore('#')
        val dangerousExts = listOf(".apk", ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".jar", ".iso", ".dmg", ".elf", ".sh")
        for (ext in dangerousExts) {
            if (cleanPath.endsWith(ext) || cleanPath.contains("$ext/")) {
                threats.add("Suspicious executable application payload in URL path ($ext)")
                break
            }
        }
        return threats
    }

    private fun detectPathTraversalOrNullByte(rawUrl: String): List<String> {
        val threats = mutableListOf<String>()
        if (rawUrl.contains("..") || rawUrl.contains("%2e%2e", ignoreCase = true) || rawUrl.contains("%252e", ignoreCase = true)) {
            threats.add("Directory traversal sequence (../) in URL path")
        }
        if (rawUrl.contains("%00") || rawUrl.contains("\u0000")) {
            threats.add("Null-byte (%00) injection in URL path")
        }
        return threats
    }

    private fun calculateEntropy(str: String): Double {
        if (str.isEmpty()) return 0.0
        val freqMap = mutableMapOf<Char, Int>()
        for (c in str) {
            freqMap[c] = freqMap.getOrDefault(c, 0) + 1
        }
        var entropy = 0.0
        val len = str.length.toDouble()
        for (count in freqMap.values) {
            val p = count / len
            entropy -= p * log2(p)
        }
        return entropy
    }
}
