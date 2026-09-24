package com.example.domain

object DomainUtils {

    private val MULTI_PART_TLDS = setOf(
        // Indian Special & Banking TLDs
        "bank.in", "co.in", "gov.in", "edu.in", "net.in", "org.in", "res.in", "gen.in", "ac.in",
        // Global Multi-part TLDs
        "co.uk", "gov.uk", "ac.uk", "org.uk", "me.uk", "ltd.uk",
        "com.au", "gov.au", "edu.au", "net.au", "org.au",
        "co.jp", "ne.jp", "ac.jp", "go.jp", "or.jp",
        "com.br", "gov.br", "edu.br", "org.br",
        "com.mx", "gob.mx", "edu.mx", "org.mx",
        "com.sg", "gov.sg", "edu.sg",
        "co.nz", "govt.nz", "ac.nz",
        "com.cn", "gov.cn", "edu.cn", "net.cn",
        "com.hk", "gov.hk", "edu.hk",
        "co.za", "gov.za", "edu.za",
        "gc.ca", "gov.bc.ca", "gov.on.ca"
    )

    // Comprehensive Indian Banking & Regulatory Domains (both RBI .bank.in and legacy/subsidiary domains)
    val INDIAN_BANKING_DOMAINS = setOf(
        // Regulatory & Apex Bodies
        "rbi.org.in", "npci.org.in", "bhimupi.org.in", "upiqr.in", "idrbt.ac.in", "sebi.gov.in", "irdai.gov.in", "iba.org.in",

        // State Bank of India (SBI) - .bank.in, .sbi, .co.in, .com
        "sbi.bank.in", "onlinesbi.sbi.bank.in", "sbi.sbi", "onlinesbi.sbi", "bank.sbi", "yono.sbi",
        "sbi.co.in", "onlinesbi.com", "sbicard.com", "sbimf.com", "sbisecurities.in", "sbilife.co.in", "sbigen.in",

        // HDFC Bank
        "hdfc.bank.in", "hdfcbank.com", "hdfc.com", "netbanking.hdfcbank.com", "hdfcsec.com", "hdfclife.com", "hdfcergo.com",

        // ICICI Bank
        "icici.bank.in", "icicibank.com", "icici.com", "infinity.icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com",

        // Punjab National Bank (PNB)
        "pnb.bank.in", "pnbindia.in", "netpnb.com", "pnb.co.in",

        // Bank of Baroda (BoB)
        "bankofbaroda.bank.in", "bankofbaroda.in", "bankofbaroda.com", "bobibanking.com",

        // Axis Bank
        "axis.bank.in", "axisbank.com", "axisbank.co.in", "axisdirect.in",

        // Kotak Mahindra Bank
        "kotak.bank.in", "kotak.com", "kotaksecurities.com", "kotaklife.com",

        // Canara Bank
        "canarabank.bank.in", "canarabank.com", "canarabank.in",

        // IndusInd Bank
        "indusind.bank.in", "indusind.com", "indusnet.co.in",

        // Union Bank of India
        "unionbankofindia.bank.in", "unionbankonline.bank.in", "unionbankofindia.co.in", "unionbankonline.co.in",

        // Bank of India (BoI)
        "bankofindia.bank.in", "bankofindia.co.in", "starconnectcbs.bankofindia.com",

        // IDBI Bank
        "idbi.bank.in", "idbibank.in", "idbi.com",

        // Indian Bank
        "indianbank.bank.in", "indianbank.in", "indianbank.net.in",

        // Central Bank of India
        "centralbank.bank.in", "centralbankofindia.co.in",

        // UCO Bank
        "uco.bank.in", "ucobank.com",

        // Yes Bank
        "yes.bank.in", "yesbank.in", "yesbank.com",

        // Federal Bank
        "federal.bank.in", "federalbank.co.in", "federalbank.com",

        // IDFC FIRST Bank
        "idfcfirst.bank.in", "idfcfirstbank.com",

        // RBL Bank
        "rbl.bank.in", "rblbank.com",

        // South Indian Bank
        "southindian.bank.in", "southindianbank.com",

        // Bandhan Bank
        "bandhan.bank.in", "bandhanbank.com",

        // Punjab & Sind Bank
        "psbindia.com", "psb.bank.in",

        // Indian Overseas Bank (IOB)
        "iob.in", "iob.bank.in", "iobnet.co.in",

        // Bank of Maharashtra
        "bankofmaharashtra.in", "bankofmaharashtra.bank.in", "mahaconnect.in",

        // AU Small Finance Bank
        "au.bank.in", "aubank.in",

        // Equitas Small Finance Bank
        "equitas.bank.in", "equitasbank.com",

        // Ujjivan Small Finance Bank
        "ujjivan.bank.in", "ujjivansfb.in",

        // Payments Banks
        "paytm.bank.in", "paytmbank.com", "paytm.com",
        "airtelpayments.bank.in", "airtelbank.com", "airtel.in",
        "ippb.bank.in", "ippbonline.com", "indiapost.gov.in",
        "jio.bank.in", "jiopaymentsbank.com", "fino.bank.in", "finobank.com"
    )

    val TOP_LEGITIMATE_DOMAINS = setOf(
        // Search & Big Tech
        "google.com", "google.co.in", "google.co.uk", "google.de", "google.fr", "google.ca", "google.com.au",
        "youtube.com", "youtu.be", "gmail.com", "googleblog.com", "googledrive.com", "android.com",
        "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "onedrive.com", "bing.com",
        "apple.com", "icloud.com", "appleid.apple.com", "developer.apple.com",
        "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.co.jp", "aws.amazon.com",
        "meta.com", "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "messenger.com",
        "twitter.com", "x.com", "t.co",
        "linkedin.com", "reddit.com", "pinterest.com", "tiktok.com", "snapchat.com", "threads.net",

        // Developer & Tech Infrastructure
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com", "stackexchange.com",
        "wikipedia.org", "wikimedia.org", "w3schools.com", "mozilla.org", "developer.mozilla.org",
        "cloudflare.com", "digitalocean.com", "heroku.com", "vercel.com", "netlify.com", "render.com",
        "docker.com", "kubernetes.io", "npm.org", "npmjs.com", "pypi.org", "maven.org",
        "openai.com", "chatgpt.com", "anthropic.com", "huggingface.co",
        "medium.com", "dev.to", "hashnode.com", "substack.com", "notion.so", "figma.com", "slack.com", "zoom.us",
        "dropbox.com", "box.com", "spotify.com", "netflix.com", "hulu.com", "disneyplus.com", "twitch.tv",
        "ictkerala.org",

        // Global Financial & Banking
        "paypal.com", "paypal.me", "stripe.com", "square.com", "squareup.com", "cash.app", "venmo.com", "zellepay.com",
        "chase.com", "jpmorgan.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
        "capitalone.com", "americanexpress.com", "discover.com", "usbank.com", "pnc.com",
        "hsbc.com", "barclays.co.uk", "santander.co.uk", "lloydsbank.com", "natwest.com", "revolut.com", "wise.com",

        // Major Logistics & Postal
        "indiapost.gov.in", "ippbonline.com", "cept.gov.in",
        "usps.com", "fedex.com", "dhl.com", "dhl.de", "ups.com", "royalmail.com", "auspost.com.au", "canadapost-postescanada.ca",

        // Major News & Media
        "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com", "washingtonpost.com",
        "reuters.com", "bloomberg.com", "forbes.com", "wsj.com", "techcrunch.com", "theverge.com", "wired.com", "thehindu.com", "ndtv.com", "timesofindia.indiatimes.com", "economic-times.indiatimes.com",

        // Major E-Commerce & Travel
        "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com", "costco.com",
        "aliexpress.com", "alibaba.com", "flipkart.com", "myntra.com", "booking.com", "airbnb.com", "tripadvisor.com", "expedia.com", "makemytrip.com", "irctc.co.in"
    )

    fun extractCleanHost(rawUrl: String): String {
        val trimmed = rawUrl.trim()
        val normalized = if (!trimmed.startsWith("http://", ignoreCase = true) && !trimmed.startsWith("https://", ignoreCase = true)) {
            "http://$trimmed"
        } else {
            trimmed
        }

        return try {
            val withoutProtocol = normalized.substringAfter("://")
            val hostPart = withoutProtocol.substringBefore("/").substringBefore("?").substringBefore("#").substringBefore(":")
            hostPart.lowercase().trim()
        } catch (e: Exception) {
            ""
        }
    }

    fun extractRootDomain(host: String): String {
        val cleanHost = host.lowercase().trim()
        if (cleanHost.isBlank()) return ""

        val parts = cleanHost.split(".")
        if (parts.size <= 2) return cleanHost

        // Check if ends with multi-part TLD (e.g. .bank.in, .co.in, .gov.in, .co.uk)
        val lastTwo = "${parts[parts.size - 2]}.${parts.last()}"
        if (MULTI_PART_TLDS.contains(lastTwo) && parts.size >= 3) {
            return "${parts[parts.size - 3]}.$lastTwo"
        }

        return "${parts[parts.size - 2]}.${parts.last()}"
    }

    fun extractSubdomain(host: String): String {
        val clean = host.lowercase().trim()
        val root = extractRootDomain(clean)
        if (clean == root || clean.isBlank() || root.isBlank()) return ""
        return if (clean.endsWith(".$root")) {
            clean.removeSuffix(".$root")
        } else {
            ""
        }
    }

    /**
     * Checks if a domain is an authorized Indian Banking or Financial Regulatory entity.
     * Verified by RBI `.bank.in`, `.sbi`, `.rbi.org.in`, `.npci.org.in` or official registry.
     */
    fun isIndianBankingDomain(host: String): Boolean {
        val clean = host.lowercase().trim()
        val root = extractRootDomain(clean)
        val sub = extractSubdomain(clean)

        // If the domain contains a subdomain that is a typosquat or lookalike of a sensitive
        // banking or service keyword (e.g. 'retaii' vs 'retail'), it is NOT an authorized domain!
        if (sub.isNotBlank()) {
            val subLabels = sub.split(".", "-").filter { it.isNotBlank() }
            if (subLabels.any { TyposquattingDetector.detect(it) != null }) {
                return false
            }
        }

        // 1. Any domain ending in .sbi is State Bank of India's exclusive ICANN dot-brand gTLD
        if (clean.endsWith(".sbi") || clean == "sbi") {
            return true
        }

        // 2. Check explicit Indian banking registry (root or exact domain must be a recognized authorized bank)
        if (INDIAN_BANKING_DOMAINS.contains(clean) || INDIAN_BANKING_DOMAINS.contains(root)) {
            return true
        }

        // 3. Check subdomains of known verified Indian bank root domains
        if (INDIAN_BANKING_DOMAINS.any { bankDomain -> clean == bankDomain || clean.endsWith(".$bankDomain") }) {
            return true
        }

        return false
    }

    fun isKnownTopLegitimateDomain(host: String): Boolean {
        val clean = host.lowercase().trim()
        val root = extractRootDomain(clean)
        val sub = extractSubdomain(clean)

        // A typosquatted or lookalike subdomain invalidates legitimate status
        if (sub.isNotBlank()) {
            val subLabels = sub.split(".", "-").filter { it.isNotBlank() }
            if (subLabels.any { TyposquattingDetector.detect(it) != null }) {
                return false
            }
        }

        if (isIndianBankingDomain(clean)) {
            return true
        }

        if (TOP_LEGITIMATE_DOMAINS.contains(root) || TOP_LEGITIMATE_DOMAINS.contains(clean)) {
            return true
        }

        if (TOP_LEGITIMATE_DOMAINS.any { legitDomain -> clean == legitDomain || clean.endsWith(".$legitDomain") }) {
            return true
        }

        // Check authoritative public institutions (.gov, .edu, .mil)
        if (clean.endsWith(".gov") || clean.endsWith(".edu") || clean.endsWith(".mil") ||
            clean.endsWith(".gov.in") || clean.endsWith(".edu.in") || clean.endsWith(".gov.uk") || clean.endsWith(".ac.uk") ||
            clean.endsWith(".edu.au") || clean.endsWith(".gov.au") || clean.endsWith(".gc.ca")) {
            return true
        }

        return false
    }

    /**
     * Splits a domain or host into clean semantic tokens (words) by dots and hyphens.
     * E.g. "secure-paypa1-verify.xyz" -> ["secure", "paypa1", "verify", "xyz"]
     */
    fun extractDomainTokens(host: String): List<String> {
        return host.lowercase()
            .split(".", "-")
            .map { it.trim() }
            .filter { it.length >= 2 }
    }
}
