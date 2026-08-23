package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.domain.BrandImpersonationDetector
import com.example.domain.DomainUtils
import com.example.domain.NlpSemanticAnalyzer
import com.example.domain.ThreatIntelligenceService
import com.example.domain.UrlStructureAnalyzer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("NoPhish", appName)
  }

  @Test
  fun `test genuine global websites are classified as legitimate and safe`() {
    val githubTest = UrlStructureAnalyzer.analyze("https://github.com/login")
    assertTrue(githubTest.isKnownLegitimate)
    assertTrue(githubTest.detectedThreats.isEmpty())

    val googleTest = UrlStructureAnalyzer.analyze("https://accounts.google.com/signin/v2/identifier")
    assertTrue(googleTest.isKnownLegitimate)
    assertTrue(googleTest.detectedThreats.isEmpty())

    val appleTest = UrlStructureAnalyzer.analyze("https://developer.apple.com/documentation")
    assertTrue(appleTest.isKnownLegitimate)
    assertTrue(appleTest.detectedThreats.isEmpty())

    val wikipediaTest = UrlStructureAnalyzer.analyze("https://en.wikipedia.org/wiki/Portal:Contents")
    assertTrue(wikipediaTest.isKnownLegitimate)

    val startupsTest = BrandImpersonationDetector.evaluate("startups.com", "")
    assertFalse(startupsTest.isImpersonating)

    val metadataTest = BrandImpersonationDetector.evaluate("metadata.org", "")
    assertFalse(metadataTest.isImpersonating)
  }

  @Test
  fun `test official Indian bank domains under RBI bank in and sbi are recognized as safe`() {
    // 1. State Bank of India
    val sbiBankIn = UrlStructureAnalyzer.analyze("https://sbi.bank.in/")
    assertTrue(sbiBankIn.isKnownLegitimate)
    assertTrue(sbiBankIn.detectedThreats.isEmpty())

    val sbiOnlineBanking = UrlStructureAnalyzer.analyze("https://onlinesbi.sbi.bank.in/portal/login.htm")
    assertTrue(sbiOnlineBanking.isKnownLegitimate)

    val sbiDotSbi = UrlStructureAnalyzer.analyze("https://onlinesbi.sbi/")
    assertTrue(sbiDotSbi.isKnownLegitimate)

    val sbiLegacy = UrlStructureAnalyzer.analyze("https://www.sbi.co.in/web/personal-banking/home")
    assertTrue(sbiLegacy.isKnownLegitimate)

    // 2. HDFC Bank
    val hdfcBankIn = UrlStructureAnalyzer.analyze("https://www.hdfc.bank.in/")
    assertTrue(hdfcBankIn.isKnownLegitimate)

    val hdfcNetBanking = UrlStructureAnalyzer.analyze("https://netbanking.hdfcbank.com/netbanking/")
    assertTrue(hdfcNetBanking.isKnownLegitimate)
    val hdfcBrandCheck = BrandImpersonationDetector.evaluate("netbanking.hdfcbank.com", "HDFC Bank Netbanking login")
    assertFalse(hdfcBrandCheck.isImpersonating)

    // 3. ICICI Bank
    val iciciBankIn = UrlStructureAnalyzer.analyze("https://www.icici.bank.in/")
    assertTrue(iciciBankIn.isKnownLegitimate)

    val iciciLegacy = UrlStructureAnalyzer.analyze("https://infinity.icicibank.com/corp/AuthenticationController")
    assertTrue(iciciLegacy.isKnownLegitimate)

    // 4. Axis Bank
    val axisBankIn = UrlStructureAnalyzer.analyze("https://www.axis.bank.in/")
    assertTrue(axisBankIn.isKnownLegitimate)

    // 5. Punjab National Bank (PNB)
    val pnbBankIn = UrlStructureAnalyzer.analyze("https://pnb.bank.in/")
    assertTrue(pnbBankIn.isKnownLegitimate)

    // 6. Bank of Baroda
    val bobBankIn = UrlStructureAnalyzer.analyze("https://bankofbaroda.bank.in/")
    assertTrue(bobBankIn.isKnownLegitimate)

    // 7. Kotak Mahindra Bank
    val kotakBankIn = UrlStructureAnalyzer.analyze("https://www.kotak.bank.in/")
    assertTrue(kotakBankIn.isKnownLegitimate)

    // 8. Canara Bank, IndusInd, Union Bank
    val canara = UrlStructureAnalyzer.analyze("https://canarabank.bank.in/")
    assertTrue(canara.isKnownLegitimate)

    val indusind = UrlStructureAnalyzer.analyze("https://www.indusind.bank.in/")
    assertTrue(indusind.isKnownLegitimate)

    val unionBank = UrlStructureAnalyzer.analyze("https://unionbankofindia.bank.in/")
    assertTrue(unionBank.isKnownLegitimate)

    // 9. Reserve Bank of India (RBI) & NPCI
    val rbi = UrlStructureAnalyzer.analyze("https://www.rbi.org.in/")
    assertTrue(rbi.isKnownLegitimate)

    val npci = UrlStructureAnalyzer.analyze("https://www.npci.org.in/")
    assertTrue(npci.isKnownLegitimate)
  }

  @Test
  fun `test malicious Indian bank phishing lures are caught`() {
    // Typosquatted / third-party domain mimicking SBI
    val fakeSbi = BrandImpersonationDetector.evaluate(
      cleanHost = "sbi-kyc-verification.xyz",
      contextText = "Dear SBI customer, your account is suspended. Update KYC immediately."
    )
    assertTrue(fakeSbi.isImpersonating)
    assertEquals("State Bank of India (SBI)", fakeSbi.impersonatedBrand)

    // Typosquatted HDFC
    val fakeHdfc = BrandImpersonationDetector.evaluate(
      cleanHost = "hdfc-netbanking-points.top",
      contextText = "Claim your HDFC credit card reward points now"
    )
    assertTrue(fakeHdfc.isImpersonating)
    assertEquals("HDFC Bank", fakeHdfc.impersonatedBrand)

    // Raw IP address with bank path
    val ipTest = UrlStructureAnalyzer.analyze("http://103.25.12.88/sbi/kyc-update")
    assertTrue(ipTest.isIpAddress)
    assertTrue(ipTest.detectedThreats.isNotEmpty())
  }

  @Test
  fun `test url structure analyzer detects typosquatting and abnormal tld`() {
    val result = UrlStructureAnalyzer.analyze("http://inddiapost-tracking.top/update-address")
    assertEquals("top", result.suspiciousTld)
    assertNotNull(result.typoSquattedBrand)
    assertTrue(result.detectedThreats.isNotEmpty())
  }

  @Test
  fun `test nlp urgency analyzer detects urgency triggers`() {
    val result = NlpSemanticAnalyzer.analyze("Your package cannot be delivered. Update address within 24 hours.")
    assertTrue(result.hasUrgency)
    assertTrue(result.urgencyScore >= 50)
  }

  @Test
  fun `test brand impersonation detects brand vs domain mismatch`() {
    val result = BrandImpersonationDetector.evaluate(
      cleanHost = "inddiapost-tracking.top",
      contextText = "India Post: Your package cannot be delivered"
    )
    assertTrue(result.isImpersonating)
    assertEquals("India Post", result.impersonatedBrand)
    assertEquals("indiapost.gov.in", result.legitimateDomain)
  }

  @Test
  fun `test multiple phishing websites flagged by heuristics`() {
    val paypalTest = UrlStructureAnalyzer.analyze("https://secure-paypa1-verification.xyz/login/verify")
    assertTrue(paypalTest.detectedThreats.isNotEmpty())
    assertEquals("xyz", paypalTest.suspiciousTld)

    val netflixTest = BrandImpersonationDetector.evaluate("netflix-billing-update.club", "Update Netflix payment info")
    assertTrue(netflixTest.isImpersonating)

    val threatSignatures = ThreatIntelligenceService.evaluate("inddiapost-tracking.top", "update-address")
    assertTrue(threatSignatures.threatSignatures.isNotEmpty() || threatSignatures.matchedCampaigns.isNotEmpty())
  }
}
