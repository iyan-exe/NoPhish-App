package com.example.domain

import com.example.data.model.ThreatDatabase

data class ThreatIntelResult(
    val matchedCampaigns: List<String>,
    val threatSignatures: List<String>,
    val reputationScore: Int, // 0 (malicious) to 100 (clean)
    val ralmSummary: String
)

object ThreatIntelligenceService {

    private val SUSPICIOUS_PATH_PATTERNS = listOf(
        Regex(""".*(login|signin|logon|auth|authenticate|verify|verification|update|kyc|otp|credential|secure|wallet|passcode|reset-pwd).*""", RegexOption.IGNORE_CASE) to "Credential harvesting pattern in untrusted host path",
        Regex(""".*(package|parcel|delivery|tracking|redelivery|shipment|post|courier|consignment|customs-fee).*""", RegexOption.IGNORE_CASE) to "Smishing delivery lure pattern",
        Regex(""".*(suspended|locked|blocked|unauthorized|urgent|action-required|disabled|violation).*""", RegexOption.IGNORE_CASE) to "Account panic induction lure",
        Regex(""".*(refund|reward|bonus|lottery|winner|claim|crypto|airdrop|drainer|free-gift).*""", RegexOption.IGNORE_CASE) to "Financial bait / crypto drainer signature",
        Regex(""".*(invoice|payment-failed|billing-update|overdue|tax-refund).*""", RegexOption.IGNORE_CASE) to "Fake billing / invoice fraud signature",
        Regex(""".*(metamask|seed-phrase|recovery-phrase|trustwallet).*""", RegexOption.IGNORE_CASE) to "Web3 secret seed phrase theft lure"
    )

    fun evaluate(cleanHost: String, path: String, fullUrl: String = ""): ThreatIntelResult {
        val lowerHost = cleanHost.lowercase().trim()
        val isLegitimate = DomainUtils.isKnownTopLegitimateDomain(lowerHost)

        if (isLegitimate) {
            return ThreatIntelResult(
                matchedCampaigns = emptyList(),
                threatSignatures = emptyList(),
                reputationScore = 98,
                ralmSummary = "Domain '$cleanHost' is recognized as an authoritative verified infrastructure host."
            )
        }

        val matchedSignatures = mutableListOf<String>()
        val matchedCampaigns = mutableListOf<String>()
        var reputation = 85

        // 1. Direct match against known malicious database
        val knownThreat = ThreatDatabase.findMatchingThreat(lowerHost, fullUrl)
        if (knownThreat != null) {
            matchedCampaigns.add("${knownThreat.category}: ${knownThreat.title}")
            matchedSignatures.addAll(knownThreat.indicatorsOfCompromise)
            reputation = 0 // Instant zero reputation for blacklisted database entries
        }

        val pathAndQuery = "$path $fullUrl".lowercase()

        for ((regex, description) in SUSPICIOUS_PATH_PATTERNS) {
            if (regex.matches(pathAndQuery)) {
                matchedSignatures.add(description)
                reputation -= 20
            }
        }

        // Active threat campaigns heuristic check on untrusted domains
        val tokens = DomainUtils.extractDomainTokens(lowerHost)

        if (tokens.contains("indiapost") || tokens.contains("inddiapost")) {
            if (!lowerHost.endsWith("indiapost.gov.in")) {
                matchedCampaigns.add("India Post Redelivery Smishing Campaign")
                reputation -= 50
            }
        }

        if (tokens.contains("usps") || tokens.contains("uspspostage")) {
            if (!lowerHost.endsWith("usps.com")) {
                matchedCampaigns.add("USPS / Logistics Postal Phishing Matrix")
                reputation -= 50
            }
        }

        if (tokens.contains("paypal") || tokens.contains("paypa1")) {
            if (!lowerHost.endsWith("paypal.com")) {
                matchedCampaigns.add("PayPal Security Verification Harvesting Operation")
                reputation -= 50
            }
        }

        if (tokens.contains("office365") || tokens.contains("microsoftonline")) {
            if (!lowerHost.endsWith("microsoft.com") && !lowerHost.endsWith("office.com")) {
                matchedCampaigns.add("Microsoft 365 Device Code Phishing Pipeline")
                reputation -= 50
            }
        }

        if (tokens.contains("metamask") || tokens.contains("seedphrase") || tokens.contains("drainer") || tokens.contains("trustwallet")) {
            if (!lowerHost.endsWith("metamask.io") && !lowerHost.endsWith("trustwallet.com")) {
                matchedCampaigns.add("Cryptocurrency Web3 Drainer & Seed Harvesting Network")
                reputation -= 50
            }
        }

        if (tokens.contains("yonosbi") || tokens.contains("onlinesbi") || tokens.contains("sbi")) {
            if (!DomainUtils.isIndianBankingDomain(lowerHost)) {
                matchedCampaigns.add("Banking KYC / YONO Update Smishing Ring")
                reputation -= 50
            }
        }

        if (tokens.contains("netflix") && !lowerHost.endsWith("netflix.com")) {
            matchedCampaigns.add("Netflix Subscription Payment Renewal Scam")
            reputation -= 50
        }

        if (tokens.contains("dhl") && !lowerHost.endsWith("dhl.com") && !lowerHost.endsWith("dhl.de")) {
            matchedCampaigns.add("DHL International Customs Duty Smishing")
            reputation -= 50
        }

        if (tokens.contains("fedex") && !lowerHost.endsWith("fedex.com")) {
            matchedCampaigns.add("FedEx Exception & Delivery Address Phishing")
            reputation -= 50
        }

        if (tokens.contains("discord") && tokens.contains("nitro") && !lowerHost.endsWith("discord.com")) {
            matchedCampaigns.add("Discord Nitro Free Gift Token Hijack")
            reputation -= 50
        }

        if (tokens.contains("incometax") && !lowerHost.endsWith("incometax.gov.in")) {
            matchedCampaigns.add("Income Tax Refund Banking Credential Scam")
            reputation -= 50
        }

        if (tokens.contains("defender") || tokens.contains("trojan") || tokens.contains("mcafee")) {
            if (!lowerHost.endsWith("microsoft.com") && !lowerHost.endsWith("mcafee.com")) {
                matchedCampaigns.add("Antivirus Scareware & Remote Access Call Center Fraud")
                reputation -= 50
            }
        }

        reputation = reputation.coerceIn(0, 100)

        val summary = buildString {
            if (matchedCampaigns.isNotEmpty()) {
                append("Domain matches active threat campaign(s): ")
                append(matchedCampaigns.distinct().joinToString(", "))
                append(". ")
            }
            if (matchedSignatures.isNotEmpty()) {
                append("Triggered ${matchedSignatures.size} heuristic signature(s): ")
                append(matchedSignatures.distinct().take(2).joinToString("; "))
                append(".")
            }
            if (matchedCampaigns.isEmpty() && matchedSignatures.isEmpty()) {
                append("No threat campaign signatures found in threat intelligence index.")
            }
        }

        return ThreatIntelResult(
            matchedCampaigns = matchedCampaigns.distinct(),
            threatSignatures = matchedSignatures.distinct(),
            reputationScore = reputation,
            ralmSummary = summary
        )
    }
}
