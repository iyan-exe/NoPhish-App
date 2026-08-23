package com.example

import com.example.data.model.ThreatDatabase
import com.example.domain.BrandImpersonationDetector
import com.example.domain.DomainUtils
import com.example.domain.NlpSemanticAnalyzer
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
}
