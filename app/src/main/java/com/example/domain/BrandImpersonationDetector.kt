package com.example.domain

data class BrandImpersonationResult(
    val isImpersonating: Boolean,
    val impersonatedBrand: String?,
    val legitimateDomain: String?,
    val mismatchSeverity: String, // "None", "Low", "Medium", "High", "Critical"
    val explanation: String
)

object BrandImpersonationDetector {

    data class TargetBrand(
        val name: String,
        val keywords: List<String>,
        val officialDomains: List<String>,
        val category: String
    )

    private val TARGET_BRANDS = listOf(
        // Indian Public & Private Sector Banks
        TargetBrand(
            name = "State Bank of India (SBI)",
            keywords = listOf("sbi", "onlinesbi", "yonosbi", "yono sbi", "state bank of india", "sbi bank", "sbi reward", "sbi kyc"),
            officialDomains = listOf(
                "sbi.bank.in", "onlinesbi.sbi.bank.in", "sbi.sbi", "onlinesbi.sbi", "bank.sbi", "yono.sbi",
                "sbi.co.in", "onlinesbi.com", "sbicard.com", "sbimf.com", "sbisecurities.in", "sbilife.co.in", "sbigen.in"
            ),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "HDFC Bank",
            keywords = listOf("hdfc", "hdfcbank", "hdfc bank", "hdfc netbanking", "hdfc credit card"),
            officialDomains = listOf("hdfc.bank.in", "hdfcbank.com", "hdfc.com", "netbanking.hdfcbank.com", "hdfcsec.com", "hdfclife.com", "hdfcergo.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "ICICI Bank",
            keywords = listOf("icici", "icicibank", "icici bank", "icici netbanking", "imobile"),
            officialDomains = listOf("icici.bank.in", "icicibank.com", "icici.com", "infinity.icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Punjab National Bank (PNB)",
            keywords = listOf("pnb", "pnb bank", "punjab national bank", "pnb netbanking", "pnbindia"),
            officialDomains = listOf("pnb.bank.in", "pnbindia.in", "netpnb.com", "pnb.co.in"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Bank of Baroda",
            keywords = listOf("bank of baroda", "bankofbaroda", "bob world", "bob bank"),
            officialDomains = listOf("bankofbaroda.bank.in", "bankofbaroda.in", "bankofbaroda.com", "bobibanking.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Axis Bank",
            keywords = listOf("axis", "axisbank", "axis bank", "axis netbanking"),
            officialDomains = listOf("axis.bank.in", "axisbank.com", "axisbank.co.in", "axisdirect.in"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Kotak Mahindra Bank",
            keywords = listOf("kotak", "kotak811", "kotak bank", "kotak mahindra"),
            officialDomains = listOf("kotak.bank.in", "kotak.com", "kotaksecurities.com", "kotaklife.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Canara Bank",
            keywords = listOf("canara", "canarabank", "canara bank", "canara netbanking"),
            officialDomains = listOf("canarabank.bank.in", "canarabank.com", "canarabank.in"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "IndusInd Bank",
            keywords = listOf("indusind", "indusind bank", "indusnet"),
            officialDomains = listOf("indusind.bank.in", "indusind.com", "indusnet.co.in"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Union Bank of India",
            keywords = listOf("union bank", "unionbank", "union bank of india", "unionbankonline"),
            officialDomains = listOf("unionbankofindia.bank.in", "unionbankonline.bank.in", "unionbankofindia.co.in", "unionbankonline.co.in"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Bank of India",
            keywords = listOf("bank of india", "bankofindia", "boi bank"),
            officialDomains = listOf("bankofindia.bank.in", "bankofindia.co.in", "starconnectcbs.bankofindia.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "IDBI Bank",
            keywords = listOf("idbi", "idbibank", "idbi bank"),
            officialDomains = listOf("idbi.bank.in", "idbibank.in", "idbi.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Indian Bank",
            keywords = listOf("indian bank", "indianbank"),
            officialDomains = listOf("indianbank.bank.in", "indianbank.in", "indianbank.net.in"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Central Bank of India",
            keywords = listOf("central bank of india", "centralbank"),
            officialDomains = listOf("centralbank.bank.in", "centralbankofindia.co.in"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "UCO Bank",
            keywords = listOf("uco bank", "ucobank"),
            officialDomains = listOf("uco.bank.in", "ucobank.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Yes Bank",
            keywords = listOf("yes bank", "yesbank"),
            officialDomains = listOf("yes.bank.in", "yesbank.in", "yesbank.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Federal Bank",
            keywords = listOf("federal bank", "federalbank"),
            officialDomains = listOf("federal.bank.in", "federalbank.co.in", "federalbank.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "IDFC FIRST Bank",
            keywords = listOf("idfc", "idfc first", "idfc first bank", "idfc bank", "idfcfirstbank"),
            officialDomains = listOf("idfcfirst.bank.in", "idfcfirstbank.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "RBL Bank",
            keywords = listOf("rbl", "rbl bank", "rblbank"),
            officialDomains = listOf("rbl.bank.in", "rblbank.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "South Indian Bank",
            keywords = listOf("south indian bank", "southindianbank"),
            officialDomains = listOf("southindian.bank.in", "southindianbank.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Bandhan Bank",
            keywords = listOf("bandhan", "bandhan bank", "bandhanbank"),
            officialDomains = listOf("bandhan.bank.in", "bandhanbank.com"),
            category = "Financial (India)"
        ),
        TargetBrand(
            name = "Reserve Bank of India (RBI)",
            keywords = listOf("rbi", "reserve bank of india", "rbi notice"),
            officialDomains = listOf("rbi.org.in"),
            category = "Apex Financial Regulator (India)"
        ),
        TargetBrand(
            name = "NPCI / UPI",
            keywords = listOf("npci", "bhim upi", "unified payments interface", "national payments corporation"),
            officialDomains = listOf("npci.org.in", "bhimupi.org.in", "upiqr.in"),
            category = "Financial Infrastructure (India)"
        ),
        TargetBrand(
            name = "Paytm / Paytm Payments Bank",
            keywords = listOf("paytm", "paytm kyc", "paytm wallet", "paytm bank"),
            officialDomains = listOf("paytm.bank.in", "paytmbank.com", "paytm.com"),
            category = "Fintech (India)"
        ),
        TargetBrand(
            name = "Airtel Payments Bank",
            keywords = listOf("airtel payments bank", "airtel payment bank", "airtel bank"),
            officialDomains = listOf("airtelpayments.bank.in", "airtelbank.com", "airtel.in"),
            category = "Fintech (India)"
        ),
        TargetBrand(
            name = "India Post",
            keywords = listOf("india post", "indiapost", "inddiapost", "speed post", "ippb", "dak seva", "postal department"),
            officialDomains = listOf("indiapost.gov.in", "ippbonline.com", "ippb.bank.in", "cept.gov.in"),
            category = "Government / Logistics (India)"
        ),
        TargetBrand(
            name = "Income Tax Department India",
            keywords = listOf("income tax", "incometax", "income tax refund", "pan card update", "pan aadhar link", "e-filing"),
            officialDomains = listOf("incometax.gov.in", "incometaxindiaefiling.gov.in", "tin-nsdl.com", "proteantech.in"),
            category = "Government (India)"
        ),
        TargetBrand(
            name = "UIDAI / Aadhaar",
            keywords = listOf("uidai", "aadhaar", "myaadhaar", "aadhar card"),
            officialDomains = listOf("uidai.gov.in", "myaadhaar.uidai.gov.in"),
            category = "Government (India)"
        ),
        TargetBrand(
            name = "EPFO",
            keywords = listOf("epfo", "epfindia", "provident fund", "pf withdrawal", "uan portal"),
            officialDomains = listOf("epfindia.gov.in", "unifiedportal-mem.epfindia.gov.in"),
            category = "Government (India)"
        ),

        // Global Tech & Financial Giants
        TargetBrand(
            name = "PayPal",
            keywords = listOf("paypal", "paypa1", "pay pal", "paypal security", "paypal dispute"),
            officialDomains = listOf("paypal.com", "paypal.me"),
            category = "Financial (Global)"
        ),
        TargetBrand(
            name = "Chase Bank",
            keywords = listOf("chase", "chase bank", "jpmorgan chase", "chase online"),
            officialDomains = listOf("chase.com", "jpmorgan.com"),
            category = "Financial (US)"
        ),
        TargetBrand(
            name = "Bank of America",
            keywords = listOf("bank of america", "bofa", "bankofamerica"),
            officialDomains = listOf("bankofamerica.com"),
            category = "Financial (US)"
        ),
        TargetBrand(
            name = "Wells Fargo",
            keywords = listOf("wells fargo", "wellsfargo"),
            officialDomains = listOf("wellsfargo.com"),
            category = "Financial (US)"
        ),
        TargetBrand(
            name = "Citibank",
            keywords = listOf("citibank", "citi bank", "citi online"),
            officialDomains = listOf("citi.com", "citibank.com", "online.citi.com"),
            category = "Financial (Global)"
        ),
        TargetBrand(
            name = "Google",
            keywords = listOf("google", "gmail", "google drive", "google security", "google workspace", "youtube"),
            officialDomains = listOf("google.com", "google.co.in", "google.co.uk", "gmail.com", "youtube.com", "accounts.google.com"),
            category = "Technology"
        ),
        TargetBrand(
            name = "Microsoft",
            keywords = listOf("microsoft", "office365", "office 365", "microsoft 365", "outlook", "onedrive", "azure"),
            officialDomains = listOf("microsoft.com", "office.com", "live.com", "outlook.com", "onedrive.com", "microsoftonline.com"),
            category = "Technology"
        ),
        TargetBrand(
            name = "Apple",
            keywords = listOf("apple", "apple id", "appleid", "icloud", "itunes", "find my iphone"),
            officialDomains = listOf("apple.com", "icloud.com", "appleid.apple.com", "developer.apple.com"),
            category = "Technology"
        ),
        TargetBrand(
            name = "Amazon",
            keywords = listOf("amazon", "amazon prime", "amazon order", "aws"),
            officialDomains = listOf("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com"),
            category = "E-Commerce"
        ),
        TargetBrand(
            name = "Netflix",
            keywords = listOf("netflix", "netflix membership", "netflix subscription", "netflix payment"),
            officialDomains = listOf("netflix.com"),
            category = "Entertainment"
        ),
        TargetBrand(
            name = "Meta / Facebook / WhatsApp / Instagram",
            keywords = listOf("facebook", "meta", "instagram", "whatsapp", "meta verified"),
            officialDomains = listOf("facebook.com", "meta.com", "instagram.com", "whatsapp.com", "fb.com"),
            category = "Social Media"
        ),
        TargetBrand(
            name = "USPS",
            keywords = listOf("usps", "united states postal service", "postal service package"),
            officialDomains = listOf("usps.com"),
            category = "Logistics (US)"
        ),
        TargetBrand(
            name = "DHL",
            keywords = listOf("dhl", "dhl express", "dhl package"),
            officialDomains = listOf("dhl.com", "dhl.de"),
            category = "Logistics (Global)"
        ),
        TargetBrand(
            name = "FedEx",
            keywords = listOf("fedex", "federal express"),
            officialDomains = listOf("fedex.com"),
            category = "Logistics (Global)"
        ),
        TargetBrand(
            name = "UPS",
            keywords = listOf("ups delivery", "ups package", "united parcel service"),
            officialDomains = listOf("ups.com"),
            category = "Logistics (Global)"
        ),
        TargetBrand(
            name = "Royal Mail",
            keywords = listOf("royal mail", "royalmail", "royal mail package", "royal mail fee"),
            officialDomains = listOf("royalmail.com", "royalmail.co.uk"),
            category = "Logistics (UK)"
        ),
        TargetBrand(
            name = "MetaMask",
            keywords = listOf("metamask", "meta mask", "metamask wallet", "secret recovery phrase"),
            officialDomains = listOf("metamask.io"),
            category = "Crypto / Web3"
        ),
        TargetBrand(
            name = "Trust Wallet",
            keywords = listOf("trust wallet", "trustwallet", "twt airdrop"),
            officialDomains = listOf("trustwallet.com"),
            category = "Crypto / Web3"
        ),
        TargetBrand(
            name = "Phantom Wallet",
            keywords = listOf("phantom wallet", "phantom solana", "phantom app"),
            officialDomains = listOf("phantom.app"),
            category = "Crypto / Web3"
        ),
        TargetBrand(
            name = "Binance",
            keywords = listOf("binance", "binance exchange", "binance kyc", "binance verification"),
            officialDomains = listOf("binance.com", "binance.us"),
            category = "Crypto / Web3"
        ),
        TargetBrand(
            name = "Coinbase",
            keywords = listOf("coinbase", "coinbase vault", "coinbase support"),
            officialDomains = listOf("coinbase.com"),
            category = "Crypto / Web3"
        ),
        TargetBrand(
            name = "Discord",
            keywords = listOf("discord", "discord nitro", "discord gift", "discord promo"),
            officialDomains = listOf("discord.com", "discord.gg"),
            category = "Social Media / Gaming"
        ),
        TargetBrand(
            name = "Telegram",
            keywords = listOf("telegram", "telegram premium", "telegram web"),
            officialDomains = listOf("telegram.org", "t.me"),
            category = "Social Media"
        ),
        TargetBrand(
            name = "Steam",
            keywords = listOf("steam", "steamcommunity", "steampowered", "steam trade"),
            officialDomains = listOf("steampowered.com", "steamcommunity.com"),
            category = "Gaming"
        ),
        TargetBrand(
            name = "IRS",
            keywords = listOf("irs", "internal revenue service", "tax stimulus", "irs refund"),
            officialDomains = listOf("irs.gov"),
            category = "Government (US)"
        ),
        TargetBrand(
            name = "HMRC",
            keywords = listOf("hmrc", "hm revenue", "tax rebate"),
            officialDomains = listOf("gov.uk", "hmrc.gov.uk"),
            category = "Government (UK)"
        ),
        TargetBrand(
            name = "Microsoft Defender",
            keywords = listOf("windows defender", "microsoft defender", "microsoft security alert", "microsoft helpline"),
            officialDomains = listOf("microsoft.com", "support.microsoft.com"),
            category = "Cybersecurity"
        ),
        TargetBrand(
            name = "McAfee",
            keywords = listOf("mcafee", "mcafee total protection", "mcafee security"),
            officialDomains = listOf("mcafee.com"),
            category = "Cybersecurity"
        ),
        TargetBrand(
            name = "Norton",
            keywords = listOf("norton", "norton 360", "norton lifelock", "norton antivirus"),
            officialDomains = listOf("norton.com", "us.norton.com"),
            category = "Cybersecurity"
        ),
        TargetBrand(
            name = "Flipkart",
            keywords = listOf("flipkart", "big billion days", "flipkart supercoins"),
            officialDomains = listOf("flipkart.com"),
            category = "E-Commerce (India)"
        ),
        TargetBrand(
            name = "Shein",
            keywords = listOf("shein", "shein gift", "shein mystery box"),
            officialDomains = listOf("shein.com"),
            category = "E-Commerce"
        )
    )

    fun evaluate(cleanHost: String, contextText: String, rawUrl: String = ""): BrandImpersonationResult {
        val hostLower = cleanHost.lowercase().trim()
        val rootDomain = DomainUtils.extractRootDomain(hostLower)
        val contextLower = contextText.lowercase()
        val domainTokens = DomainUtils.extractDomainTokens(hostLower)
        val sub = DomainUtils.extractSubdomain(hostLower)

        // 0. Subdomain Typosquatting / Impersonation Check:
        // A trusted parent domain (e.g. 'onlinesbi.sbi', 'paypal.com') must NEVER make an arbitrary
        // lookalike subdomain (e.g. 'retaii', 'retial', 'retaiI') safe!
        if (sub.isNotBlank()) {
            val subLabels = sub.split(".", "-").filter { it.isNotBlank() }
            for (label in subLabels) {
                val subMatch = TyposquattingDetector.detect(label)
                if (subMatch != null) {
                    val matchedBrand = TARGET_BRANDS.firstOrNull { brand ->
                        brand.officialDomains.any { off ->
                            hostLower == off || hostLower.endsWith(".$off") || rootDomain == off ||
                            off.endsWith(".$rootDomain") || rootDomain.endsWith(".$off")
                        } || brand.keywords.any { kw -> kw.lowercase().replace(" ", "") == subMatch.targetKeyword }
                    }

                    val brandName = matchedBrand?.name ?: "Official Banking / Service Provider"
                    val primaryOfficial = matchedBrand?.officialDomains?.firstOrNull() ?: rootDomain

                    return BrandImpersonationResult(
                        isImpersonating = true,
                        impersonatedBrand = brandName,
                        legitimateDomain = primaryOfficial,
                        mismatchSeverity = "Critical",
                        explanation = "Subdomain '$sub' on '$rootDomain' is an unauthorized lookalike/typosquat of official $brandName service '${subMatch.targetKeyword}' ('$label' imitates '${subMatch.targetKeyword}'). Official portal is '$primaryOfficial'."
                    )
                }
            }
        }

        // 1. If domain is RBI-regulated .bank.in, State Bank of India's .sbi, or Indian Banking Domain:
        if (DomainUtils.isIndianBankingDomain(hostLower)) {
            val matchedBrand = TARGET_BRANDS.firstOrNull { brand ->
                brand.officialDomains.any { off -> hostLower == off || hostLower.endsWith(".$off") || rootDomain == off }
            } ?: TargetBrand("Verified Indian Banking Institution", emptyList(), listOf(hostLower), "Financial (India)")

            return BrandImpersonationResult(
                isImpersonating = false,
                impersonatedBrand = matchedBrand.name,
                legitimateDomain = hostLower,
                mismatchSeverity = "None",
                explanation = "Domain '$cleanHost' is an authorized and official ${matchedBrand.name} banking portal."
            )
        }

        // 2. If host matches any known legitimate authority or whitelist directly:
        if (DomainUtils.isKnownTopLegitimateDomain(hostLower)) {
            return BrandImpersonationResult(
                isImpersonating = false,
                impersonatedBrand = null,
                legitimateDomain = cleanHost,
                mismatchSeverity = "None",
                explanation = "Domain '$cleanHost' is a verified legitimate entity."
            )
        }

        // 3. Evaluate each brand against discrete tokens in domain and context
        for (brand in TARGET_BRANDS) {
            val isOfficialHost = brand.officialDomains.any { offDomain ->
                hostLower == offDomain ||
                hostLower.endsWith(".$offDomain") ||
                rootDomain == offDomain
            }

            if (isOfficialHost) {
                return BrandImpersonationResult(
                    isImpersonating = false,
                    impersonatedBrand = brand.name,
                    legitimateDomain = brand.officialDomains.first(),
                    mismatchSeverity = "None",
                    explanation = "Domain '$cleanHost' is an authorized official portal for ${brand.name}."
                )
            }

            // Check if domain tokens mimic brand
            val domainMimicsBrand = brand.keywords.any { keyword ->
                val cleanKw = keyword.lowercase().replace(" ", "")
                if (cleanKw.length <= 4) {
                    // For short keywords (sbi, pnb, meta, rbl, ups, dhl), require exact token match or hyphenated token match
                    domainTokens.any { token ->
                        token == cleanKw || token.startsWith("$cleanKw-") || token.endsWith("-$cleanKw")
                    }
                } else {
                    domainTokens.any { token ->
                        token == cleanKw ||
                        token.startsWith("$cleanKw-") ||
                        token.endsWith("-$cleanKw") ||
                        (token.contains(cleanKw) && !DomainUtils.isKnownTopLegitimateDomain(token)) ||
                        isTyposquatMatch(token, cleanKw)
                    }
                }
            }

            // Check if context text or raw URL path explicitly references this brand
            val contextMentionsBrand = brand.keywords.any { keyword ->
                containsWordOrPhrase(contextLower, keyword)
            }
            val pathMentionsBrand = if (rawUrl.isNotEmpty()) {
                val pathAndQuery = rawUrl.substringAfter(cleanHost, "").lowercase()
                brand.keywords.any { keyword ->
                    val cleanKw = keyword.lowercase().replace(" ", "")
                    if (cleanKw.length >= 4) {
                        pathAndQuery.contains(cleanKw)
                    } else false
                }
            } else false

            // If an untrusted domain claims or mimics this brand in domain or path
            if (domainMimicsBrand || ((contextMentionsBrand || pathMentionsBrand) && !isOfficialHost)) {
                val primaryOfficial = brand.officialDomains.first()
                val severity = if (domainMimicsBrand || pathMentionsBrand) "Critical" else "High"

                return BrandImpersonationResult(
                    isImpersonating = true,
                    impersonatedBrand = brand.name,
                    legitimateDomain = primaryOfficial,
                    mismatchSeverity = severity,
                    explanation = "Brand '${brand.name}' is referenced in the domain or path, but destination host '$cleanHost' is NOT the official portal ('$primaryOfficial'). This is a severe brand spoofing indicator."
                )
            }
        }

        return BrandImpersonationResult(
            isImpersonating = false,
            impersonatedBrand = null,
            legitimateDomain = null,
            mismatchSeverity = "None",
            explanation = "No brand impersonation or spoofing detected for '$cleanHost'."
        )
    }

    private fun isTyposquatMatch(token: String, keyword: String): Boolean {
        if (token.length < 5 || keyword.length < 5) return false
        if (token.contains(keyword)) return true
        val dist = levenshtein(token, keyword)
        return dist in 1..2
    }

    private fun levenshtein(s1: String, s2: String): Int {
        val dp = Array(s1.length + 1) { IntArray(s2.length + 1) }
        for (i in 0..s1.length) dp[i][0] = i
        for (j in 0..s2.length) dp[0][j] = j
        for (i in 1..s1.length) {
            for (j in 1..s2.length) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                dp[i][j] = minOf(
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + cost
                )
            }
        }
        return dp[s1.length][s2.length]
    }

    private fun containsWordOrPhrase(text: String, phrase: String): Boolean {
        val lowerText = text.lowercase()
        val lowerPhrase = phrase.lowercase()
        if (lowerPhrase.length <= 4) {
            val regex = Regex("\\b${Regex.escape(lowerPhrase)}\\b")
            return regex.containsMatchIn(lowerText)
        }
        return lowerText.contains(lowerPhrase)
    }
}
