package com.example.domain

import kotlin.math.ln
import kotlin.math.sqrt

data class ThreatDocument(
    val id: String,
    val title: String,
    val category: String,
    val targetBrand: String,
    val content: String,
    val indicatorsOfCompromise: List<String>,
    val attackVector: String,
    val severity: String,
    val recommendedAction: String
)

data class RetrievedRagMatch(
    val document: ThreatDocument,
    val cosineSimilarity: Float,
    val matchedTerms: List<String>,
    val relevanceScorePercent: Float
)

data class RagRetrievalResult(
    val query: String,
    val topMatches: List<RetrievedRagMatch>,
    val highestSimilarity: Float,
    val matchedCampaignTitle: String?,
    val ragContextForPrompt: String,
    val isKnownThreatRetrieved: Boolean
)

/**
 * Real Retrieval-Augmented Language Model (RALM) & Semantic Vector Store.
 *
 * Implements a genuine Vector Space Model (VSM) using Term Frequency - Inverse Document Frequency (TF-IDF)
 * and Cosine Similarity to retrieve matching cyber threat intelligence documents,
 * campaign signatures, and indicators of compromise (IOCs) from a curated knowledge corpus.
 */
object RagThreatRetriever {

    private val STOP_WORDS = setOf(
        "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
        "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but",
        "by", "can", "did", "do", "does", "doing", "don", "down", "during", "each", "few", "for",
        "from", "further", "had", "has", "have", "having", "he", "her", "here", "hers", "herself",
        "him", "himself", "his", "how", "i", "if", "in", "into", "is", "it", "its", "itself", "just",
        "me", "more", "most", "my", "myself", "no", "nor", "not", "now", "of", "off", "on", "once",
        "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own", "s", "same", "she",
        "should", "so", "some", "such", "t", "than", "that", "the", "their", "theirs", "them",
        "themselves", "then", "there", "these", "they", "this", "those", "through", "to", "too",
        "under", "until", "up", "very", "was", "we", "were", "what", "when", "where", "which",
        "while", "who", "whom", "why", "will", "with", "you", "your", "yours", "yourself"
    )

    val THREAT_CORPUS: List<ThreatDocument> = listOf(
        ThreatDocument(
            id = "CORPUS-001",
            title = "SBI YONO KYC Suspension Smishing Matrix",
            category = "Banking",
            targetBrand = "State Bank of India",
            content = "State Bank of India SBI YONO netbanking KYC PAN card update account blocked suspended frozen within 24 hours fake login page credential harvester APK malware download retail onlinesbi",
            indicatorsOfCompromise = listOf("sbi-kyc-verification.top", "onlinesbi.sbi.banking-verification.xyz", "/retail/l0gin", "sbi-pan-update.apk"),
            attackVector = "SMS / WhatsApp urgency pretext claiming account deactivation unless KYC is updated via unofficial domain",
            severity = "CRITICAL",
            recommendedAction = "Verify only at official https://onlinesbi.sbi or https://bank.sbi. Never enter OTP or PAN on non-.sbi/.bank.in domains."
        ),
        ThreatDocument(
            id = "CORPUS-002",
            title = "India Post Redelivery Surcharge Lure",
            category = "Postal Logistics",
            targetBrand = "India Post",
            content = "India Post parcel package delivery hold failed missing street house number customs surcharge fee tracking consignment update address redelivery fee payment indiapost speed post",
            indicatorsOfCompromise = listOf("indiapost-parcel-fee.buzz", "indiapost-redelivery.icu", "speedpost-address-update.click"),
            attackVector = "Mass SMS smishing claiming undelivered parcel requiring nominal payment of ₹25-₹50 to steal credit/debit card numbers and CVV",
            severity = "HIGH",
            recommendedAction = "Track parcels exclusively on https://indiapost.gov.in. India Post never sends SMS demanding delivery hold charges."
        ),
        ThreatDocument(
            id = "CORPUS-003",
            title = "HDFC NetBanking Credential Harvesting Operation",
            category = "Banking",
            targetBrand = "HDFC Bank",
            content = "HDFC Bank NetBanking customer ID IPIN password locked restricted reward points redemption credit card limit increase login verification portal hdfc",
            indicatorsOfCompromise = listOf("hdfcbk-netbanking-login.xyz", "hdfc-rewards-claim.buzz", "hdfcbank.com.login-portal.top"),
            attackVector = "Spoofed netbanking login screen capturing Customer ID, IPIN, and one-time password (OTP) in real time",
            severity = "CRITICAL",
            recommendedAction = "Always check for https://netbanking.hdfcbank.com. Do not click links claiming urgent netbanking unlocking."
        ),
        ThreatDocument(
            id = "CORPUS-004",
            title = "MetaMask & Web3 Token Airdrop Drainer",
            category = "Cryptocurrency",
            targetBrand = "MetaMask / Web3",
            content = "MetaMask wallet seed phrase secret recovery 12 words private key airdrop claim token bonus usdt ethereum connect wallet drainer smart contract approval",
            indicatorsOfCompromise = listOf("claim-airdrop-metamask.live", "metamask-seedphrase-restore.surf", "trustwallet-bonus.rest"),
            attackVector = "Greed lure offering free token airdrops prompting users to type their 12-word seed phrase or sign malicious permit signatures",
            severity = "CRITICAL",
            recommendedAction = "Never type recovery seed phrase online. Legitimate airdrops never request private keys or seed phrases."
        ),
        ThreatDocument(
            id = "CORPUS-005",
            title = "State Electricity Board Power Disconnection Scam",
            category = "Utility",
            targetBrand = "Electricity Board / Bijli Bill",
            content = "Electricity power will be disconnected tonight at 9:30 PM unpaid bill electricity office contact officer pay now bijli bill update online apk",
            indicatorsOfCompromise = listOf("bijli-bill-update.online", "electricity-power-disconnect.cam", "power-bill-payment.top"),
            attackVector = "Coercive urgency threat sent in late afternoon threatening imminent power cut to induce panic bill payment or remote screen sharing APK install",
            severity = "HIGH",
            recommendedAction = "Pay power bills exclusively through official DISCOM state portals or verified consumer apps."
        ),
        ThreatDocument(
            id = "CORPUS-006",
            title = "USPS & International Postal Customs Scam",
            category = "Postal Logistics",
            targetBrand = "USPS / DHL / FedEx",
            content = "USPS United States Postal Service package hold incomplete address customs duty tracking redelivery confirm street number fedex dhl",
            indicatorsOfCompromise = listOf("usps-postage-fee-redelivery.top", "fedex-package-hold.click", "dhl-express-duty.club"),
            attackVector = "Smishing targeting online shoppers claiming shipment suspended awaiting customs clearance fees",
            severity = "HIGH",
            recommendedAction = "Verify on official usps.com, fedex.com, or dhl.com directly."
        ),
        ThreatDocument(
            id = "CORPUS-007",
            title = "PayPal Account Restriction & Billing Pretext",
            category = "Financial",
            targetBrand = "PayPal",
            content = "PayPal account limited restricted unauthorized transaction invoice overdue cancel payment verify identity billing update paypal signin",
            indicatorsOfCompromise = listOf("paypal-account-security.top", "paypal-restricted-verify.cfd", "paypal.com.account-update.pw"),
            attackVector = "Phishing email/SMS displaying a fabricated high-value transaction with a fake dispute resolution link",
            severity = "HIGH",
            recommendedAction = "Log in directly to https://www.paypal.com from a fresh browser tab to inspect actual account notices."
        ),
        ThreatDocument(
            id = "CORPUS-008",
            title = "Official State Bank of India Institutional Banking Portal",
            category = "Legitimate Authority",
            targetBrand = "State Bank of India",
            content = "Official State Bank of India SBI online banking retail portal internet banking onlinesbi.sbi sbi.bank.in bank.sbi authorized secure banking",
            indicatorsOfCompromise = listOf("https://retail.onlinesbi.sbi/retail/login.htm", "https://sbi.bank.in", "https://bank.sbi"),
            attackVector = "None. Verified legitimate financial infrastructure.",
            severity = "SAFE",
            recommendedAction = "Legitimate banking resource. Maintain safe browsing habits."
        ),
        ThreatDocument(
            id = "CORPUS-009",
            title = "Government Regulatory & Identity Repositories",
            category = "Legitimate Authority",
            targetBrand = "Government of India / RBI",
            content = "Reserve Bank of India RBI NPCI UPI bhim incometax indiapost official government portal verified regulatory registry gov.in",
            indicatorsOfCompromise = listOf("https://rbi.org.in", "https://npci.org.in", "https://indiapost.gov.in"),
            attackVector = "None. Official sovereign regulatory registry.",
            severity = "SAFE",
            recommendedAction = "Legitimate government agency domain."
        )
    )

    // Vocabulary & IDF tables computed on initialization
    private val vocabulary: List<String>
    private val idfMap: Map<String, Float>
    private val docVectors: List<FloatArray>

    init {
        // Build vocabulary from corpus
        val termDocCounts = mutableMapOf<String, Int>()
        val tokenizedDocs = THREAT_CORPUS.map { doc ->
            val text = "${doc.title} ${doc.targetBrand} ${doc.category} ${doc.content} ${doc.indicatorsOfCompromise.joinToString(" ")}"
            tokenize(text)
        }

        tokenizedDocs.forEach { tokens ->
            tokens.distinct().forEach { term ->
                termDocCounts[term] = (termDocCounts[term] ?: 0) + 1
            }
        }

        vocabulary = termDocCounts.keys.sorted()
        val numDocs = THREAT_CORPUS.size.toDouble()

        // Compute smooth IDF: ln(1 + (N / DF))
        idfMap = vocabulary.associateWith { term ->
            val df = termDocCounts[term] ?: 1
            ln(1.0 + (numDocs / df.toDouble())).toFloat()
        }

        // Compute normalized TF-IDF vector for every document
        docVectors = tokenizedDocs.map { tokens ->
            computeTfIdfVector(tokens)
        }
    }

    private fun tokenize(text: String): List<String> {
        return text.lowercase()
            .split(Regex("[^a-zA-Z0-9]+"))
            .filter { it.length >= 2 && !STOP_WORDS.contains(it) }
    }

    private fun computeTfIdfVector(tokens: List<String>): FloatArray {
        val vector = FloatArray(vocabulary.size)
        if (tokens.isEmpty()) return vector

        val termFreqs = mutableMapOf<String, Int>()
        for (t in tokens) {
            termFreqs[t] = (termFreqs[t] ?: 0) + 1
        }
        val totalTokens = tokens.size.toFloat()

        var sumSquares = 0.0f
        for (i in vocabulary.indices) {
            val term = vocabulary[i]
            val count = termFreqs[term] ?: 0
            if (count > 0) {
                val tf = count.toFloat() / totalTokens
                val idf = idfMap[term] ?: 1.0f
                val tfidf = tf * idf
                vector[i] = tfidf
                sumSquares += tfidf * tfidf
            }
        }

        // L2 Unit Normalization
        val norm = sqrt(sumSquares)
        if (norm > 1e-6f) {
            for (i in vector.indices) {
                vector[i] /= norm
            }
        }
        return vector
    }

    private fun cosineSimilarity(v1: FloatArray, v2: FloatArray): Float {
        var dot = 0.0f
        for (i in v1.indices) {
            dot += v1[i] * v2[i]
        }
        return dot.coerceIn(0.0f, 1.0f)
    }

    /**
     * Executes real semantic retrieval across the threat corpus.
     * Computes TF-IDF vector of query text and returns cosine similarities.
     */
    fun retrieve(queryText: String, topK: Int = 3): RagRetrievalResult {
        val queryTokens = tokenize(queryText)
        val queryVector = computeTfIdfVector(queryTokens)

        val matches = mutableListOf<RetrievedRagMatch>()

        for (i in THREAT_CORPUS.indices) {
            val doc = THREAT_CORPUS[i]
            val docVector = docVectors[i]
            val similarity = cosineSimilarity(queryVector, docVector)

            // Identify matched terms between query and document
            val docTokens = tokenize("${doc.title} ${doc.content}").toSet()
            val matchedTerms = queryTokens.filter { docTokens.contains(it) }.distinct()

            if (similarity > 0.05f || matchedTerms.isNotEmpty()) {
                matches.add(
                    RetrievedRagMatch(
                        document = doc,
                        cosineSimilarity = similarity,
                        matchedTerms = matchedTerms.take(6),
                        relevanceScorePercent = (similarity * 100.0f)
                    )
                )
            }
        }

        val sortedMatches = matches.sortedByDescending { it.cosineSimilarity }.take(topK)
        val top = sortedMatches.firstOrNull()
        val highestSim = top?.cosineSimilarity ?: 0.0f
        val isThreat = highestSim >= 0.25f && top?.document?.severity != "SAFE"

        val contextBuilder = StringBuilder()
        contextBuilder.append("RETRIEVED THREAT INTELLIGENCE (Vector Space Cosine Retrieval):\n")
        if (sortedMatches.isEmpty()) {
            contextBuilder.append("No direct threat campaign match found in verified intelligence corpus.\n")
        } else {
            sortedMatches.forEachIndexed { idx, match ->
                val doc = match.document
                contextBuilder.append("${idx + 1}. [${doc.id}] ${doc.title} (${"%.1f".format(match.relevanceScorePercent)}% Cosine Match)\n")
                contextBuilder.append("   - Category: ${doc.category} | Severity: ${doc.severity}\n")
                contextBuilder.append("   - Attack Vector: ${doc.attackVector}\n")
                contextBuilder.append("   - Matched IOCs/Terms: ${match.matchedTerms.joinToString(", ")}\n")
            }
        }

        return RagRetrievalResult(
            query = queryText,
            topMatches = sortedMatches,
            highestSimilarity = highestSim,
            matchedCampaignTitle = if (highestSim >= 0.20f) top?.document?.title else null,
            ragContextForPrompt = contextBuilder.toString(),
            isKnownThreatRetrieved = isThreat
        )
    }
}
