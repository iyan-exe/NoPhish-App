package com.example.domain

import com.example.data.model.EvidenceItem
import com.example.data.model.EvidenceSeverity
import java.net.URI
import java.util.Locale

data class HtmlAnalysisResult(
    val hasLoginForm: Boolean = false,
    val hasPasswordField: Boolean = false,
    val hasExternalFormAction: Boolean = false,
    val externalFormActionUrl: String? = null,
    val hasInsecureHttpForm: Boolean = false,
    val hasHiddenInputs: Boolean = false,
    val hiddenInputCount: Int = 0,
    val hasIframes: Boolean = false,
    val iframeSources: List<String> = emptyList(),
    val hasObfuscatedJs: Boolean = false,
    val obfuscationTechniques: List<String> = emptyList(),
    val hasExternalScripts: Boolean = false,
    val suspiciousExternalScripts: List<String> = emptyList(),
    val hasMetaRedirect: Boolean = false,
    val metaRedirectTarget: String? = null,
    val hasSuspiciousDownloadLinks: Boolean = false,
    val suspiciousDownloads: List<String> = emptyList(),
    val htmlRiskScore: Int = 0,
    val evidence: List<EvidenceItem> = emptyList(),
    val summary: String = ""
)

/**
 * Sandboxed HTML & Webpage Security Analyzer.
 *
 * Inspects page structure, credential harvesting forms, external submission targets,
 * hidden overlays, obfuscated scripts, and suspicious downloads WITHOUT executing untrusted code.
 */
object HtmlWebpageAnalyzer {

    private val SUSPICIOUS_DOWNLOAD_EXTENSIONS = setOf(
        ".exe", ".scr", ".bat", ".apk", ".vbs", ".iso", ".msi", ".cmd", ".ps1", ".hta"
    )

    private val SENSITIVE_INPUT_KEYWORDS = listOf(
        "password", "passwd", "pwd", "pass", "pin", "otp", "ssn", "social_security",
        "card_number", "cardnumber", "cvv", "cvc", "creditcard", "debitcard", "bank_account",
        "seedphrase", "secret_recovery", "private_key", "mothers_maiden"
    )

    fun analyze(htmlContent: String, baseUrl: String = ""): HtmlAnalysisResult {
        if (htmlContent.isBlank()) {
            return HtmlAnalysisResult(summary = "No webpage content provided for analysis.")
        }

        val baseHost = DomainUtils.extractCleanHost(baseUrl)
        val lowerHtml = htmlContent.lowercase(Locale.ROOT)
        val evidenceList = mutableListOf<EvidenceItem>()
        var riskScore = 0

        // 1. Password input detection
        val hasPassword = lowerHtml.contains("type=\"password\"") || lowerHtml.contains("type='password'")
        if (hasPassword) {
            riskScore += 15
            evidenceList.add(
                EvidenceItem(
                    category = "HTML Analysis",
                    title = "Password Input Field Detected",
                    description = "Webpage contains a password input field for collecting user credentials.",
                    severity = EvidenceSeverity.MEDIUM,
                    indicator = "<input type=\"password\">"
                )
            )
        }

        // 2. Sensitive credential field detection
        val detectedSensitiveFields = mutableListOf<String>()
        for (keyword in SENSITIVE_INPUT_KEYWORDS) {
            if (lowerHtml.contains("name=\"$keyword\"") || lowerHtml.contains("name='$keyword'") ||
                lowerHtml.contains("id=\"$keyword\"") || lowerHtml.contains("id='$keyword'") ||
                lowerHtml.contains("placeholder=\"*$keyword\"")
            ) {
                detectedSensitiveFields.add(keyword)
            }
        }

        val hasLoginForm = hasPassword || detectedSensitiveFields.isNotEmpty()

        // 3. Form action destinations & external submissions
        var hasExternalAction = false
        var externalActionUrl: String? = null
        var hasInsecureForm = false

        val formActionRegex = Regex("""<form[^>]*action=["']([^"']*)["']""", RegexOption.IGNORE_CASE)
        val formMatches = formActionRegex.findAll(htmlContent)

        for (match in formMatches) {
            val action = match.groupValues.getOrNull(1)?.trim() ?: continue
            if (action.startsWith("http://", ignoreCase = true)) {
                hasInsecureForm = true
            }

            if (action.startsWith("http://", ignoreCase = true) || action.startsWith("https://", ignoreCase = true)) {
                val actionHost = DomainUtils.extractCleanHost(action)
                if (baseHost.isNotBlank() && actionHost.isNotBlank() &&
                    !actionHost.equals(baseHost, ignoreCase = true) &&
                    !actionHost.endsWith(".$baseHost") &&
                    !baseHost.endsWith(".$actionHost")
                ) {
                    hasExternalAction = true
                    externalActionUrl = action
                    break
                }
            }
        }

        if (hasExternalAction) {
            riskScore += 55
            evidenceList.add(
                EvidenceItem(
                    category = "HTML Analysis",
                    title = "External Form Submission Destination",
                    description = "Form submits sensitive data to an external, mismatched domain: $externalActionUrl",
                    severity = EvidenceSeverity.CRITICAL,
                    indicator = "Action: $externalActionUrl"
                )
            )
        }

        if (hasInsecureForm && hasLoginForm) {
            riskScore += 35
            evidenceList.add(
                EvidenceItem(
                    category = "HTML Analysis",
                    title = "Insecure HTTP Form Submission",
                    description = "Credential form transmits sensitive inputs over unencrypted HTTP.",
                    severity = EvidenceSeverity.HIGH,
                    indicator = "HTTP form action detected"
                )
            )
        }

        // 4. Hidden Inputs
        val hiddenInputRegex = Regex("""<input[^>]*type=["']hidden["'][^>]*>""", RegexOption.IGNORE_CASE)
        val hiddenCount = hiddenInputRegex.findAll(htmlContent).count()
        val hasHidden = hiddenCount > 0

        // 5. Iframes
        val iframeRegex = Regex("""<iframe[^>]*src=["']([^"']*)["']""", RegexOption.IGNORE_CASE)
        val iframeSources = iframeRegex.findAll(htmlContent).map { it.groupValues[1] }.toList()
        val hasIframes = iframeSources.isNotEmpty()

        if (hasIframes) {
            val hiddenIframe = lowerHtml.contains("display:none") || lowerHtml.contains("visibility:hidden") ||
                    lowerHtml.contains("width=\"0\"") || lowerHtml.contains("height=\"0\"")
            if (hiddenIframe) {
                riskScore += 30
                evidenceList.add(
                    EvidenceItem(
                        category = "HTML Analysis",
                        title = "Hidden Overlay Iframe",
                        description = "Webpage renders hidden iframe overlays commonly used in clickjacking or credential siphoning.",
                        severity = EvidenceSeverity.HIGH,
                        indicator = "Hidden <iframe>"
                    )
                )
            }
        }

        // 6. Suspicious / Obfuscated JavaScript
        val obfuscationTechniques = mutableListOf<String>()
        if (lowerHtml.contains("eval(") || lowerHtml.contains("eval (")) {
            obfuscationTechniques.add("eval() execution")
        }
        if (lowerHtml.contains("unescape(") || lowerHtml.contains("string.fromcharcode(")) {
            obfuscationTechniques.add("CharCode/Unescape unpacking")
        }
        if (Regex("""\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}""").containsMatchIn(htmlContent)) {
            obfuscationTechniques.add("Hexadecimal string encoding")
        }
        if (lowerHtml.contains("atob(") && lowerHtml.contains("<script")) {
            obfuscationTechniques.add("Base64 script decoding")
        }

        val hasObfuscatedJs = obfuscationTechniques.isNotEmpty()
        if (hasObfuscatedJs) {
            riskScore += 35
            evidenceList.add(
                EvidenceItem(
                    category = "HTML Analysis",
                    title = "Obfuscated JavaScript Detected",
                    description = "Detected suspicious client-side code packing: ${obfuscationTechniques.joinToString(", ")}",
                    severity = EvidenceSeverity.HIGH,
                    indicator = obfuscationTechniques.first()
                )
            )
        }

        // 7. Meta-refresh redirect
        val metaRefreshRegex = Regex("""<meta[^>]*http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"']*)["']""", RegexOption.IGNORE_CASE)
        val metaMatch = metaRefreshRegex.find(htmlContent)
        val metaTarget = metaMatch?.groupValues?.getOrNull(1)?.trim()
        val hasMetaRedirect = metaTarget != null

        if (hasMetaRedirect) {
            riskScore += 25
            evidenceList.add(
                EvidenceItem(
                    category = "HTML Analysis",
                    title = "Automated Meta-Refresh Redirect",
                    description = "Page triggers an automatic browser redirect to target: $metaTarget",
                    severity = EvidenceSeverity.MEDIUM,
                    indicator = "Meta refresh: $metaTarget"
                )
            )
        }

        // 8. Suspicious direct downloads
        val suspiciousDownloads = mutableListOf<String>()
        val hrefRegex = Regex("""href=["']([^"']*)["']""", RegexOption.IGNORE_CASE)
        for (hrefMatch in hrefRegex.findAll(htmlContent)) {
            val link = hrefMatch.groupValues.getOrNull(1) ?: continue
            val cleanLink = link.substringBefore("?").substringBefore("#").lowercase()
            for (ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS) {
                if (cleanLink.endsWith(ext)) {
                    suspiciousDownloads.add(link)
                }
            }
        }

        val hasDownloads = suspiciousDownloads.isNotEmpty()
        if (hasDownloads) {
            riskScore += 45
            evidenceList.add(
                EvidenceItem(
                    category = "HTML Analysis",
                    title = "Direct Executable / Script Payload Download",
                    description = "Page links directly to dangerous downloadable binaries or scripts: ${suspiciousDownloads.take(2).joinToString()}",
                    severity = EvidenceSeverity.CRITICAL,
                    indicator = suspiciousDownloads.first()
                )
            )
        }

        val summary = buildString {
            if (hasExternalAction) append("CRITICAL: Login form submits credentials to foreign domain. ")
            if (hasLoginForm) append("Credential harvesting form detected. ")
            if (hasObfuscatedJs) append("Obfuscated scripts found (${obfuscationTechniques.joinToString()}). ")
            if (hasDownloads) append("Suspicious downloadable binary link found. ")
            if (isEmpty()) append("Clean HTML structure: no credential harvesting or malicious obfuscation patterns found.")
        }.trim()

        return HtmlAnalysisResult(
            hasLoginForm = hasLoginForm,
            hasPasswordField = hasPassword,
            hasExternalFormAction = hasExternalAction,
            externalFormActionUrl = externalActionUrl,
            hasInsecureHttpForm = hasInsecureForm,
            hasHiddenInputs = hasHidden,
            hiddenInputCount = hiddenCount,
            hasIframes = hasIframes,
            iframeSources = iframeSources,
            hasObfuscatedJs = hasObfuscatedJs,
            obfuscationTechniques = obfuscationTechniques,
            hasExternalScripts = false,
            suspiciousExternalScripts = emptyList(),
            hasMetaRedirect = hasMetaRedirect,
            metaRedirectTarget = metaTarget,
            hasSuspiciousDownloadLinks = hasDownloads,
            suspiciousDownloads = suspiciousDownloads,
            htmlRiskScore = riskScore.coerceIn(0, 100),
            evidence = evidenceList,
            summary = summary
        )
    }
}
