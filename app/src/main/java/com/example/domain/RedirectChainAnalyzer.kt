package com.example.domain

import com.example.data.model.EvidenceItem
import com.example.data.model.EvidenceSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

data class RedirectHop(
    val step: Int,
    val url: String,
    val host: String,
    val isShortener: Boolean,
    val statusCode: Int = 302
)

data class RedirectChainResult(
    val originalUrl: String,
    val finalUrl: String,
    val hops: List<RedirectHop> = emptyList(),
    val totalHops: Int = 0,
    val hasExcessiveRedirects: Boolean = false,
    val involvesShortener: Boolean = false,
    val hasDomainSwitch: Boolean = false,
    val hasSuspiciousFinalDomain: Boolean = false,
    val hasOpenRedirectParam: Boolean = false,
    val redirectRiskScore: Int = 0,
    val evidence: List<EvidenceItem> = emptyList(),
    val summary: String = ""
)

/**
 * Redirect Chain Inspector.
 *
 * Traces navigation paths through URL shorteners, tracking intermediate relays,
 * open redirects, and final landing domains.
 */
object RedirectChainAnalyzer {

    private val KNOWN_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly",
        "goo.gl", "rebrand.ly", "shorturl.at", "bl.ink", "trib.al"
    )

    private val OPEN_REDIRECT_PARAMS = setOf(
        "url", "redirect", "next", "dest", "destination", "target", "return", "return_url", "r", "goto", "out"
    )

    fun isUrlShortener(host: String): Boolean {
        val cleanHost = DomainUtils.extractCleanHost(host)
        val root = DomainUtils.extractRootDomain(cleanHost)
        return KNOWN_SHORTENERS.contains(cleanHost) || KNOWN_SHORTENERS.contains(root)
    }

    /**
     * Inspects an explicitly provided chain of URLs or a single URL for redirect anomalies.
     */
    fun analyzeChain(urls: List<String>): RedirectChainResult {
        if (urls.isEmpty()) {
            return RedirectChainResult(originalUrl = "", finalUrl = "", summary = "No URL provided for redirect inspection.")
        }

        val original = urls.first().trim()
        val finalUrl = urls.last().trim()
        val evidenceList = mutableListOf<EvidenceItem>()
        var riskScore = 0

        val hops = urls.mapIndexed { index, u ->
            val host = DomainUtils.extractCleanHost(u)
            RedirectHop(
                step = index + 1,
                url = u,
                host = host,
                isShortener = isUrlShortener(host)
            )
        }

        val totalHops = hops.size - 1
        val hasExcessiveRedirects = totalHops >= 3
        val involvesShortener = hops.any { it.isShortener }

        val originalHost = DomainUtils.extractCleanHost(original)
        val finalHost = DomainUtils.extractCleanHost(finalUrl)
        val hasDomainSwitch = originalHost.isNotBlank() && finalHost.isNotBlank() &&
                !originalHost.equals(finalHost, ignoreCase = true)

        // Check for open redirect parameters in the original URL
        var hasOpenRedirectParam = false
        if (original.contains("?")) {
            val query = original.substringAfter("?")
            val params = query.split("&").map { it.substringBefore("=").lowercase().trim() }
            if (params.any { OPEN_REDIRECT_PARAMS.contains(it) }) {
                hasOpenRedirectParam = true
            }
        }

        if (hasOpenRedirectParam) {
            riskScore += 45
            evidenceList.add(
                EvidenceItem(
                    category = "Redirect Analysis",
                    title = "Open Redirect Parameter",
                    description = "URL contains an unvalidated redirect parameter ($original) that can bounce victims to arbitrary attacker sites.",
                    severity = EvidenceSeverity.HIGH,
                    indicator = "Open redirect candidate"
                )
            )
        }

        if (involvesShortener) {
            riskScore += 25
            evidenceList.add(
                EvidenceItem(
                    category = "Redirect Analysis",
                    title = "URL Shortener Cloaking",
                    description = "Navigation passes through a URL shortening service (${hops.firstOrNull { it.isShortener }?.host}) to conceal the final destination.",
                    severity = EvidenceSeverity.MEDIUM,
                    indicator = "Shortener detected"
                )
            )
        }

        if (hasExcessiveRedirects) {
            riskScore += 20
            evidenceList.add(
                EvidenceItem(
                    category = "Redirect Analysis",
                    title = "Excessive Redirect Hops",
                    description = "Chain contains $totalHops redirect hops, characteristic of evasive phishing relay infrastructure.",
                    severity = EvidenceSeverity.MEDIUM,
                    indicator = "$totalHops hops"
                )
            )
        }

        if (hasDomainSwitch && involvesShortener) {
            evidenceList.add(
                EvidenceItem(
                    category = "Redirect Analysis",
                    title = "Cross-Domain Transition",
                    description = "Shortened link redirects from $originalHost to destination domain $finalHost.",
                    severity = EvidenceSeverity.LOW,
                    indicator = "$originalHost -> $finalHost"
                )
            )
        }

        val summary = buildString {
            if (hasOpenRedirectParam) append("Open redirect parameter detected. ")
            if (involvesShortener) append("URL shortener used to conceal destination. ")
            if (hasDomainSwitch) append("Redirects to $finalHost. ")
            if (hasExcessiveRedirects) append("Excessive redirect count ($totalHops hops). ")
            if (isEmpty()) append("Direct navigation with no malicious redirect evasion detected.")
        }.trim()

        return RedirectChainResult(
            originalUrl = original,
            finalUrl = finalUrl,
            hops = hops,
            totalHops = totalHops,
            hasExcessiveRedirects = hasExcessiveRedirects,
            involvesShortener = involvesShortener,
            hasDomainSwitch = hasDomainSwitch,
            hasSuspiciousFinalDomain = false,
            hasOpenRedirectParam = hasOpenRedirectParam,
            redirectRiskScore = riskScore.coerceIn(0, 100),
            evidence = evidenceList,
            summary = summary
        )
    }

    /**
     * Resolves redirects safely using OkHttp with strict 3-second timeout and HEAD requests,
     * without executing scripts or downloading full responses.
     */
    suspend fun resolveRedirectsSafely(targetUrl: String): RedirectChainResult = withContext(Dispatchers.IO) {
        val chain = mutableListOf(targetUrl)

        val client = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .build()

        var current = targetUrl
        var hopsCount = 0
        val maxHops = 5

        while (hopsCount < maxHops) {
            val normalized = if (!current.startsWith("http://", ignoreCase = true) && !current.startsWith("https://", ignoreCase = true)) {
                "https://$current"
            } else current

            try {
                val request = Request.Builder()
                    .url(normalized)
                    .head()
                    .header("User-Agent", "Mozilla/5.0 (NoPhish-Security-Scanner/2.0)")
                    .build()

                client.newCall(request).execute().use { response ->
                    val code = response.code
                    if (code in 300..399) {
                        val location = response.header("Location")
                        if (!location.isNullOrBlank()) {
                            val nextUrl = if (location.startsWith("/")) {
                                val hostPart = normalized.substringBefore("://") + "://" + DomainUtils.extractCleanHost(normalized)
                                hostPart + location
                            } else {
                                location
                            }
                            chain.add(nextUrl)
                            current = nextUrl
                            hopsCount++
                        } else {
                            return@withContext analyzeChain(chain)
                        }
                    } else {
                        return@withContext analyzeChain(chain)
                    }
                }
            } catch (e: Exception) {
                // If network connection fails, analyze what we have statically
                break
            }
        }

        analyzeChain(chain)
    }
}
