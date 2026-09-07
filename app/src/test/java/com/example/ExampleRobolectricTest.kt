package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.domain.BrandImpersonationDetector
import com.example.domain.DomainUtils
import com.example.domain.NlpSemanticAnalyzer
import com.example.domain.PhishingDetectorEngine
import com.example.domain.RagThreatRetriever
import com.example.domain.SupervisedUrlClassifier
import com.example.domain.ThreatIntelligenceService
import com.example.domain.UrlStructureAnalyzer
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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

  @Test
  fun `test supervised url classifier predicts phishing accurately`() {
    val phishingMl = com.example.domain.SupervisedUrlClassifier.predict("http://sbi-yono-kyc-update.xyz/login.php")
    assertTrue(phishingMl.probability > 0.60f)
    assertTrue(phishingMl.isPhishing)
    assertTrue(phishingMl.topContributors.isNotEmpty())

    val safeMl = com.example.domain.SupervisedUrlClassifier.predict("https://sbi.bank.in/portal/web/home")
    assertTrue(safeMl.probability < 0.20f)
    assertFalse(safeMl.isPhishing)
  }

  @Test
  fun `test rag threat retriever computes cosine similarity on vector space model`() {
    val ragResult = com.example.domain.RagThreatRetriever.retrieve("metamask restore secret seed recovery phrase")
    assertTrue(ragResult.highestSimilarity > 0.20f)
    assertNotNull(ragResult.matchedCampaignTitle)
    assertTrue(ragResult.topMatches.isNotEmpty())
  }

  @Test
  fun `test retail onlinesbi sbi with leetspeak l0gin is flagged as phishing not zero risk`() {
    val urlWithTamperedPath = "https://retail.onlinesbi.sbi/retail/l0gin"
    val analysis = UrlStructureAnalyzer.analyze(urlWithTamperedPath)
    assertTrue(analysis.hasPathObfuscation)
    assertTrue(analysis.detectedThreats.any { it.contains("l0gin", ignoreCase = true) || it.contains("leetspeak", ignoreCase = true) })

    val db = com.example.data.local.PhishShieldDatabase.getDatabase(androidx.test.core.app.ApplicationProvider.getApplicationContext())
    val engine = com.example.domain.PhishingDetectorEngine(db.whitelistDao())

    kotlinx.coroutines.runBlocking {
      val result = engine.analyze(urlWithTamperedPath, "")
      assertTrue("Risk score should be high due to path deception, got: ${result.riskScore}", result.riskScore >= 65)
      assertEquals("Phishing", result.status)
      assertTrue(result.detectedThreats.isNotEmpty())
    }
  }

  @Test
  fun `test official retail onlinesbi sbi login htm is verified safe`() {
    val officialUrl = "https://retail.onlinesbi.sbi/retail/login.htm"
    val analysis = UrlStructureAnalyzer.analyze(officialUrl)
    assertFalse(analysis.hasPathObfuscation)

    val db = com.example.data.local.PhishShieldDatabase.getDatabase(androidx.test.core.app.ApplicationProvider.getApplicationContext())
    val engine = com.example.domain.PhishingDetectorEngine(db.whitelistDao())

    kotlinx.coroutines.runBlocking {
      val result = engine.analyze(officialUrl, "")
      assertTrue("Risk score for official portal should be <= 10, got: ${result.riskScore}", result.riskScore <= 10)
      assertEquals("Safe", result.status)
    }
  }

  @Test
  fun `test whitelisted domain with open redirect is not marked safe`() {
    val whitelistedWithRedirect = "https://www.google.com/url?q=http://phishing-site.xyz/login"
    val db = com.example.data.local.PhishShieldDatabase.getDatabase(androidx.test.core.app.ApplicationProvider.getApplicationContext())
    val engine = com.example.domain.PhishingDetectorEngine(db.whitelistDao())

    kotlinx.coroutines.runBlocking {
      val result = engine.analyze(whitelistedWithRedirect, "")
      assertTrue("Whitelisted domain with open redirect must have high risk score, got: ${result.riskScore}", result.riskScore >= 65)
      assertNotEquals("Safe", result.status)
      assertTrue(result.detectedThreats.any { it.contains("redirect", ignoreCase = true) })
    }
  }

  @Test
  fun `test whitelisted domain with apk payload is not marked safe`() {
    val whitelistedWithApk = "https://sbi.bank.in/downloads/app_update.apk"
    val db = com.example.data.local.PhishShieldDatabase.getDatabase(androidx.test.core.app.ApplicationProvider.getApplicationContext())
    val engine = com.example.domain.PhishingDetectorEngine(db.whitelistDao())

    kotlinx.coroutines.runBlocking {
      val result = engine.analyze(whitelistedWithApk, "")
      assertTrue("Whitelisted domain with APK payload must have high risk score, got: ${result.riskScore}", result.riskScore >= 65)
      assertNotEquals("Safe", result.status)
      assertTrue(result.detectedThreats.any { it.contains(".apk", ignoreCase = true) })
    }
  }

  @Test
  fun `test evaluation on 20 unseen phishing and 20 unseen legitimate URLs`() {
    val unseenLegit = listOf(
      "https://www.bloomberg.com/markets",
      "https://www.theguardian.com/international",
      "https://www.nature.com/articles/nature",
      "https://www.nih.gov/health-information",
      "https://stackoverflow.blog/2024/01/ai-trends/",
      "https://slack.engineering/architecture-at-scale/",
      "https://aws.amazon.com/ec2/pricing/",
      "https://azure.microsoft.com/en-us/solutions/",
      "https://www.costco.com/warehouse-locations",
      "https://www.ikea.com/us/en/cat/furniture-fu001/",
      "https://www.bestbuy.com/site/electronics/audio",
      "https://www.espn.com/nba/story",
      "https://www.nationalgeographic.com/environment",
      "https://www.coursera.org/browse/data-science",
      "https://www.udemy.com/topic/python/",
      "https://www.atlassian.com/software/jira",
      "https://www.oracle.com/database/technologies/",
      "https://www.salesforce.com/products/what-is-salesforce/",
      "https://www.fidelity.com/trading/overview",
      "https://www.schwab.com/brokerage"
    )

    val unseenPhish = listOf(
      "http://chase-bank-verify-device-alert.top/signin",
      "http://citibank-card-fraud-freeze.buzz/auth.php",
      "http://appleid-security-unlock-device.work/login",
      "http://microsoft-onedrive-expired-file.icu/view",
      "http://netflix-reactivate-subscription-hold.cfd/update",
      "http://amazon-prime-unusual-activity-hold.top/verify",
      "http://paypal-resolution-center-case99.xyz/confirm",
      "http://binance-kyc-compliance-check.live/wallet",
      "http://coinbase-fraud-protection-case.click/auth",
      "http://198.51.100.45/secure/bankofamerica/login.html",
      "http://203.0.113.19:8080/portal/secure-login.php",
      "http://dhl-express-redelivery-tax.top/parcel",
      "http://fedex-clearance-invoice-payment.buzz/shipment",
      "http://ups-customs-duty-unpaid.icu/tracking",
      "http://usps-address-confirm-reschedule.click/fee",
      "http://sbi-card-statement-unpaid-charges.shop/pay",
      "http://hdfc-bank-bonus-reward-points.site/redeem",
      "http://icici-direct-instant-loan-approval.online/kyc",
      "http://metamask-security-audit-airdrop.surf/connect",
      "http://phantom-solana-drainer-claim.live/auth"
    )

    var tp = 0
    var fn = 0
    var tn = 0
    var fp = 0

    println("=== EVALUATING UNSEEN PHISHING URLS ===")
    for (url in unseenPhish) {
      val res = com.example.domain.SupervisedUrlClassifier.predict(url)
      println("PHISH: p=${"%.4f".format(res.probability)} isPhish=${res.isPhishing} url=$url")
      if (res.isPhishing) {
        tp++
      } else {
        fn++
      }
    }

    println("=== EVALUATING UNSEEN LEGITIMATE URLS ===")
    for (url in unseenLegit) {
      val res = com.example.domain.SupervisedUrlClassifier.predict(url)
      println("LEGIT: p=${"%.4f".format(res.probability)} isPhish=${res.isPhishing} url=$url")
      if (!res.isPhishing) {
        tn++
      } else {
        fp++
      }
    }

    println("=== EVALUATION SUMMARY ===")
    println("Total Phishing: ${unseenPhish.size}, Detected: $tp, Missed (FN): $fn")
    println("Total Legit: ${unseenLegit.size}, Correct (TN): $tn, False Alarms (FP): $fp")
    val pdr = tp.toDouble() / unseenPhish.size.toDouble() * 100.0
    val ldr = tn.toDouble() / unseenLegit.size.toDouble() * 100.0
    println("Phishing Detection Rate: $pdr%")
    println("Legitimate Detection Rate: $ldr%")
    println("False Positives: $fp")
    println("False Negatives: $fn")
  }

  @Test
  fun `test kotlin inference parameters exactly match exported trained_model_json artifact`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val jsonString = try {
      context.assets.open("trained_model.json").bufferedReader().use { it.readText() }
    } catch (e: Exception) {
      val file = java.io.File("trained_model.json")
      if (file.exists()) file.readText() else java.io.File("../trained_model.json").readText()
    }

    val json = org.json.JSONObject(jsonString)
    val version = json.getString("model_version")
    val checksum = json.getString("model_checksum")
    val bias = json.getDouble("bias").toFloat()
    val weightsArray = json.getJSONArray("weights")
    val meansArray = json.getJSONArray("means")
    val stdsArray = json.getJSONArray("stds")

    assertEquals("Model version must match exactly", version, com.example.domain.SupervisedUrlClassifier.MODEL_VERSION)
    assertEquals("Model checksum must match exactly", checksum, com.example.domain.SupervisedUrlClassifier.MODEL_CHECKSUM)
    assertEquals("Bias must match within 1e-5 tolerance", bias, com.example.domain.SupervisedUrlClassifier.BIAS, 1e-5f)

    assertEquals("Weights dimension must be 24", 24, weightsArray.length())
    assertEquals("Means dimension must be 24", 24, meansArray.length())
    assertEquals("Stds dimension must be 24", 24, stdsArray.length())

    for (i in 0 until 24) {
      val expectedWeight = weightsArray.getDouble(i).toFloat()
      val actualWeight = com.example.domain.SupervisedUrlClassifier.WEIGHTS[i]
      assertEquals("Weight index $i must match", expectedWeight, actualWeight, 1e-5f)

      val expectedMean = meansArray.getDouble(i).toFloat()
      val actualMean = com.example.domain.SupervisedUrlClassifier.FEATURE_MEANS[i]
      assertEquals("Mean index $i must match", expectedMean, actualMean, 1e-5f)

      val expectedStd = stdsArray.getDouble(i).toFloat()
      val actualStd = com.example.domain.SupervisedUrlClassifier.FEATURE_STDS[i]
      assertEquals("Std index $i must match", expectedStd, actualStd, 1e-5f)
    }
  }

  @Test
  fun `test sbi case sensitive lookalike path produces suspicious signal and never automatic phishing`() = runBlocking {
    val db = com.example.data.local.PhishShieldDatabase.getDatabase(ApplicationProvider.getApplicationContext())
    val engine = PhishingDetectorEngine(db.whitelistDao())
    val sbiLookalikeUrl = "https://retail.onlinesbi.sbi/retaiI/login.html"

    val result = engine.analyze(sbiLookalikeUrl, "")

    // 1. Never automatically classify legitimate domain as phishing
    assertEquals("Should produce Suspicious status, NOT Phishing", "Suspicious", result.status)
    // 2. Produces a low/suspicious signal (score 35)
    assertEquals(35, result.riskScore)
    // 3. User explanation provides clear warnings about the lookalike path while noting domain legitimacy
    assertTrue(
      "Explanation must warn of lookalike path",
      result.userExplanation.contains("lookalike") || result.userExplanation.contains("retaiI")
    )
    assertTrue(
      "Detected threats must report the lookalike path segment",
      result.detectedThreats.any { threat -> threat.contains("retaiI") && threat.contains("retail") }
    )
  }

  @Test
  fun `test legitimate sbi clean path produces safe verdict`() = runBlocking {
    val db = com.example.data.local.PhishShieldDatabase.getDatabase(ApplicationProvider.getApplicationContext())
    val engine = PhishingDetectorEngine(db.whitelistDao())
    val sbiCleanUrl = "https://retail.onlinesbi.sbi/retail/login.html"

    val result = engine.analyze(sbiCleanUrl, "")

    assertEquals("Safe", result.status)
    assertEquals(0, result.riskScore)
    assertTrue(result.detectedThreats.isEmpty())
  }

  @Test
  fun `test open redirect on legitimate sbi domain escalates to phishing and never allows whitelist to override`() = runBlocking {
    val db = com.example.data.local.PhishShieldDatabase.getDatabase(ApplicationProvider.getApplicationContext())
    val engine = PhishingDetectorEngine(db.whitelistDao())
    val openRedirectUrl = "https://retail.onlinesbi.sbi/redirect?url=http://attacker-phishing.xyz/login"

    val result = engine.analyze(openRedirectUrl, "")

    assertEquals("Phishing", result.status)
    assertTrue("Risk score should escalate to at least 65 due to open redirect", result.riskScore >= 65)
    assertTrue(
      "Detected threats must explicitly include open redirect pointing to external target",
      result.detectedThreats.any { threat -> threat.contains("Open Redirect") && threat.contains("attacker-phishing.xyz") }
    )
  }

  @Test
  fun `test sbi path transposition retial produces suspicious status and score 35`() = runBlocking {
    val db = com.example.data.local.PhishShieldDatabase.getDatabase(ApplicationProvider.getApplicationContext())
    val engine = PhishingDetectorEngine(db.whitelistDao())
    val testUrl = "https://retail.onlinesbi.sbi/retial/login.html"

    val urlAnalysis = UrlStructureAnalyzer.analyze(testUrl)
    val brandCheck = BrandImpersonationDetector.evaluate(urlAnalysis.cleanHost, "", testUrl)
    val mlResult = SupervisedUrlClassifier.predict(testUrl)
    val threatIntel = ThreatIntelligenceService.evaluate(urlAnalysis.cleanHost, urlAnalysis.path, testUrl)
    val ragResult = RagThreatRetriever.retrieve("$testUrl  ${urlAnalysis.cleanHost} ${urlAnalysis.path} lookalike path typo")
    val nlpResult = NlpSemanticAnalyzer.analyze("")

    val result = engine.analyze(testUrl, "")

    println("=== RUNTIME DETECTION PIPELINE AUDIT FOR: $testUrl ===")
    println("LAYER 1 [UrlStructureAnalyzer]: host='${urlAnalysis.cleanHost}', rootDomain='${urlAnalysis.rootDomain}', isKnownLegitimate=${urlAnalysis.isKnownLegitimate}, hasPathLookalike=${urlAnalysis.hasPathLookalike}, hasPathObfuscation=${urlAnalysis.hasPathObfuscation}, hasOpenRedirect=${urlAnalysis.hasOpenRedirect}, threats=${urlAnalysis.detectedThreats}")
    println("LAYER 2 [BrandImpersonationDetector]: isImpersonating=${brandCheck.isImpersonating}, brand=${brandCheck.impersonatedBrand}")
    println("LAYER 3 [SupervisedUrlClassifier ML]: isPhishing=${mlResult.isPhishing}, probability=${mlResult.probability}, confidence=${mlResult.confidencePercentage}%")
    println("LAYER 4 [RagThreatRetriever]: topMatch=${ragResult.matchedCampaignTitle}, similarity=${ragResult.highestSimilarity}")
    println("LAYER 5 [ThreatIntelligenceService]: reputation=${threatIntel.reputationScore}, signatures=${threatIntel.threatSignatures}")
    println("LAYER 6 [NlpSemanticAnalyzer]: hasUrgency=${nlpResult.hasUrgency}, urgencyScore=${nlpResult.urgencyScore}")
    println("LAYER 7 [Final Risk Engine]: STATUS='${result.status}', RISK_SCORE=${result.riskScore}/100, THREATS=${result.detectedThreats}")
    println("EXPLANATION: ${result.userExplanation}")
    println("=========================================================")

    // 1. Never automatically classify legitimate domain as phishing due to path typo
    assertEquals("Should produce Suspicious status, NOT Phishing", "Suspicious", result.status)
    // 2. Score must be 35 (Suspicious / Low tier)
    assertEquals(35, result.riskScore)
    // 3. User explanation warns about the path anomaly while recognizing legitimate institution
    assertTrue(
      "Explanation must warn of path typo / lookalike",
      result.userExplanation.contains("retial") || result.userExplanation.contains("retail") ||
      result.userExplanation.contains("lookalike") || result.userExplanation.contains("transposition") ||
      result.userExplanation.contains("typo")
    )
    // 4. Detected threats must contain the specific transposition flag
    assertTrue(
      "Detected threats must report retial transposition",
      result.detectedThreats.any { threat -> threat.contains("retial") && threat.contains("retail") }
    )
  }
}
