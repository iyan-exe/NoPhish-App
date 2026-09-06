package com.example

import com.example.data.model.ThreatDatabase
import com.example.domain.BrandImpersonationDetector
import com.example.domain.DomainUtils
import com.example.domain.NlpSemanticAnalyzer
import com.example.domain.RagThreatRetriever
import com.example.domain.SupervisedUrlClassifier
import com.example.domain.ThreatIntelligenceService
import com.example.domain.UrlStructureAnalyzer
import org.junit.Assert.*
import org.junit.Test

class ExampleUnitTest {

    @Test
    fun testThreatDatabaseHasComprehensiveEntries() {
        assertTrue(ThreatDatabase.KNOWN_FAKE_WEBSITES.size >= 20)
        val categories = ThreatDatabase.KNOWN_FAKE_WEBSITES.map { it.category }.distinct()
        assertTrue(categories.contains("Banking"))
        assertTrue(categories.contains("Smishing / Postal"))
        assertTrue(categories.contains("Crypto / Web3"))
        assertTrue(categories.contains("Social Media"))
        assertTrue(categories.contains("Tax / Gov"))
        assertTrue(categories.contains("Scareware"))
        assertTrue(categories.contains("E-Commerce"))
    }

    @Test
    fun testKnownFakeWebsitesMatchInThreatIntelService() {
        val sbiFake = ThreatDatabase.KNOWN_FAKE_WEBSITES.first { it.id == "bank_sbi_yono" }
        val eval = ThreatIntelligenceService.evaluate(sbiFake.fakeDomain, "/login.php", sbiFake.sampleUrl)
        assertEquals(0, eval.reputationScore)
        assertTrue(eval.matchedCampaigns.isNotEmpty())
    }

    @Test
    fun testMetaMaskSeedDrainerDetection() {
        val url = "https://metamask-seedphrase-restore.link/validate-wallet"
        val structure = UrlStructureAnalyzer.analyze(url)
        val threatIntel = ThreatIntelligenceService.evaluate(structure.cleanHost, structure.path, url)
        val nlp = NlpSemanticAnalyzer.analyze("Enter your 12-word Secret Recovery Phrase to prevent token loss within 24 hours.")

        assertEquals("link", structure.suspiciousTld)
        assertTrue(threatIntel.matchedCampaigns.any { it.contains("Web3") || it.contains("MetaMask") || it.contains("Crypto") })
        assertTrue(nlp.hasUrgency)
    }

    @Test
    fun testPostalSmishingTyposquattingDetection() {
        val brandCheck = BrandImpersonationDetector.evaluate(
            cleanHost = "inddiapost-tracking.top",
            contextText = "Your package cannot be delivered due to incomplete address. Please update address within 24 hours."
        )
        assertTrue(brandCheck.isImpersonating)
        assertEquals("India Post", brandCheck.impersonatedBrand)
    }

    @Test
    fun testLegitimateOfficialBankingDomainsAreSafe() {
        assertTrue(DomainUtils.isIndianBankingDomain("sbi.bank.in"))
        assertTrue(DomainUtils.isIndianBankingDomain("onlinesbi.sbi"))
        assertTrue(DomainUtils.isIndianBankingDomain("hdfc.bank.in"))
        assertTrue(DomainUtils.isKnownTopLegitimateDomain("indiapost.gov.in"))
        assertTrue(DomainUtils.isKnownTopLegitimateDomain("google.com"))

        val brandCheck = BrandImpersonationDetector.evaluate("sbi.bank.in", "State Bank of India")
        assertFalse(brandCheck.isImpersonating)
    }

    @Test
    fun testLeetspeakPathObfuscationDetection() {
        val sbiLeetspeakUrl = "https://retail.onlinesbi.sbi/retail/l0gin"
        val structure = UrlStructureAnalyzer.analyze(sbiLeetspeakUrl)
        assertTrue(structure.hasPathObfuscation)
        assertTrue(structure.detectedThreats.any { it.contains("l0gin") && it.contains("login") })

        val sbiCleanUrl = "https://retail.onlinesbi.sbi/retail/login"
        val cleanStructure = UrlStructureAnalyzer.analyze(sbiCleanUrl)
        assertFalse(cleanStructure.hasPathObfuscation)
        assertTrue(cleanStructure.detectedThreats.isEmpty())
    }

    @Test
    fun testSupervisedModelMetadataAndInferenceParity() {
        assertEquals("v1.1.0-stratified", SupervisedUrlClassifier.MODEL_VERSION)
        assertNotNull(SupervisedUrlClassifier.MODEL_CHECKSUM)
        assertEquals(24, SupervisedUrlClassifier.FEATURE_MEANS.size)
        assertEquals(24, SupervisedUrlClassifier.FEATURE_STDS.size)
        assertEquals(24, SupervisedUrlClassifier.WEIGHTS.size)

        val maliciousUrl = "http://secure-login.bank-update.xyz/verify?token=123"
        val mlResult = SupervisedUrlClassifier.predict(maliciousUrl)
        assertTrue("Model should flag high probability for suspicious token-stuffed URL", mlResult.probability > 0.5f)
        assertTrue(mlResult.topContributors.isNotEmpty())

        val benignUrl = "https://www.google.com/search?q=cybersecurity"
        val benignResult = SupervisedUrlClassifier.predict(benignUrl)
        assertTrue("Benign search URL should have low phishing probability", benignResult.probability < 0.5f)
    }

    @Test
    fun testRagThreatRetrieverCosineRetrieval() {
        val result = RagThreatRetriever.retrieve("SBI YONO netbanking KYC PAN update blocked account")
        assertNotNull(result.matchedCampaignTitle)
        assertTrue(result.highestSimilarity > 0.15f)
        assertTrue(result.topMatches.any { it.document.targetBrand.contains("State Bank of India") })

        val safeResult = RagThreatRetriever.retrieve("RBI regulatory circular reserve bank of india official")
        assertTrue(safeResult.topMatches.any { it.document.category == "Legitimate Authority" })
    }

    @Test
    fun testNlpObfuscationAndHomoglyphDetection() {
        // Cyrillic 'а' (U+0430) and 'о' (U+043E) replacing Latin letters
        val homoglyphText = "Urgent: Upd\u0430te y\u043Eur b\u0430nk KYC now or account suspended!"
        val nlp = NlpSemanticAnalyzer.analyze(homoglyphText)
        assertTrue(nlp.hasObfuscation)
        assertTrue(nlp.hasUrgency)
        assertTrue(nlp.pressureTactics.any { 
            it.contains("homoglyph", ignoreCase = true) || 
            it.contains("suspension", ignoreCase = true) || 
            it.contains("deadline", ignoreCase = true) 
        })

        // Zero-width space injection
        val zeroWidthText = "Account\u200Blocked\u200BImmediately"
        val zwResult = NlpSemanticAnalyzer.analyze(zeroWidthText)
        assertTrue(zwResult.hasObfuscation)
    }

    @Test
    fun testUrlStructureDangerousPayloadAndOpenRedirect() {
        val apkUrl = "http://sbi-support.buzz/download/sbi_yono_update.apk"
        val apkAnalysis = UrlStructureAnalyzer.analyze(apkUrl)
        assertTrue(apkAnalysis.hasSuspiciousPayload)
        assertTrue(apkAnalysis.detectedThreats.any { it.contains(".apk") })

        val openRedirectUrl = "https://legit-service.com/login?redirect=http://malicious-site.top"
        val redirectAnalysis = UrlStructureAnalyzer.analyze(openRedirectUrl)
        assertTrue(redirectAnalysis.hasOpenRedirect)

        val ipUrl = "http://192.168.1.50/bank/login"
        val ipAnalysis = UrlStructureAnalyzer.analyze(ipUrl)
        assertTrue(ipAnalysis.isIpAddress)

        val atUrl = "http://legitbank.com@attacker-controlled.top/auth"
        val atAnalysis = UrlStructureAnalyzer.analyze(atUrl)
        assertTrue(atAnalysis.hasAtSymbolTrick)
    }

    @Test
    fun testBrandImpersonationInPathOnUntrustedHost() {
        val pathSpoofUrl = "http://198.51.100.45/secure/bankofamerica/login.html"
        val brandCheck = BrandImpersonationDetector.evaluate(
            cleanHost = "198.51.100.45",
            contextText = "",
            rawUrl = pathSpoofUrl
        )
        assertTrue(brandCheck.isImpersonating)
        assertEquals("Bank of America", brandCheck.impersonatedBrand)
    }

    @Test
    fun testSbiCaseSensitiveLookalikePathManipulationEdgeCase() {
        // Exact real-world edge case:
        // Host is legitimate SBI production domain, but path contains 'retaiI' (uppercase 'I' instead of 'l')
        val testUrl = "https://retail.onlinesbi.sbi/retaiI/login.html"
        val analyzer = UrlStructureAnalyzer.analyze(testUrl)

        // 1. Host verification: Registrable domain is verified legitimate SBI domain
        assertEquals("retail.onlinesbi.sbi", analyzer.cleanHost)
        assertTrue("Legitimate SBI host must be recognized as known legitimate", analyzer.isKnownLegitimate)

        // 2. Lookalike detection: Case-sensitive visual manipulation detected without marking as digit leetspeak
        assertTrue("URL path should flag hasPathLookalike for 'retaiI' spoofing 'retail'", analyzer.hasPathLookalike)
        assertFalse("Case-sensitive lookalike must NOT be falsely marked as digit leetspeak", analyzer.hasPathObfuscation)
        assertTrue(
            "Threat list should contain descriptive lookalike warning",
            analyzer.detectedThreats.any { it.contains("retaiI") && it.contains("retail") }
        )
        assertTrue(
            "Explanation should note legitimate domain while warning of lookalike path",
            analyzer.explanation.contains("lookalike") || analyzer.explanation.contains("retail.onlinesbi.sbi")
        )
    }

    @Test
    fun testCleanSbiPathIsSafe() {
        val testUrl = "https://retail.onlinesbi.sbi/retail/login.html"
        val analyzer = UrlStructureAnalyzer.analyze(testUrl)

        assertTrue(analyzer.isKnownLegitimate)
        assertFalse(analyzer.hasPathLookalike)
        assertFalse(analyzer.hasPathObfuscation)
        assertFalse(analyzer.hasOpenRedirect)
        assertTrue(analyzer.detectedThreats.isEmpty())
    }

    @Test
    fun testOpenRedirectOnLegitimateDomainNeverBlindlyTrusted() {
        // Attack: Attacker leverages legitimate SBI domain with an open redirect to an external phishing target
        val redirectUrl = "https://retail.onlinesbi.sbi/redirect?url=http://attacker-phishing.xyz/login"
        val analyzer = UrlStructureAnalyzer.analyze(redirectUrl)

        assertTrue("Host is recognized as SBI legitimate domain", analyzer.isKnownLegitimate)
        assertTrue("Open redirect parameter must be flagged", analyzer.hasOpenRedirect)
        assertTrue(
            "Detected threats must report open redirect pointing to external target",
            analyzer.detectedThreats.any { it.contains("Open Redirect") && it.contains("attacker-phishing.xyz") }
        )
    }

    @Test
    fun testSameDomainRedirectNotFlaggedAsOpenRedirect() {
        val safeRedirectUrl = "https://retail.onlinesbi.sbi/login?redirect=https://retail.onlinesbi.sbi/retail/login.html"
        val analyzer = UrlStructureAnalyzer.analyze(safeRedirectUrl)

        assertFalse("Same-domain redirect should NOT be flagged as malicious open redirect", analyzer.hasOpenRedirect)
    }
}

