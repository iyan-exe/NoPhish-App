package com.example.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.PhishShieldDatabase
import com.example.data.model.AnalysisBreakdown
import com.example.data.model.PhishingAnalysisResult
import com.example.data.model.PresetScenario
import com.example.data.model.ScanHistoryEntity
import com.example.data.model.WhitelistEntity
import com.example.domain.PhishingDetectorEngine
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val db = PhishShieldDatabase.getDatabase(application)
    private val scanHistoryDao = db.scanHistoryDao()
    private val whitelistDao = db.whitelistDao()
    private val engine = PhishingDetectorEngine(whitelistDao)

    private val moshi = Moshi.Builder().build()
    private val listStringType = Types.newParameterizedType(List::class.java, String::class.java)
    private val stringListAdapter = moshi.adapter<List<String>>(listStringType)

    // Input States
    private val _urlInput = MutableStateFlow("")
    val urlInput: StateFlow<String> = _urlInput.asStateFlow()

    private val _contextInput = MutableStateFlow("")
    val contextInput: StateFlow<String> = _contextInput.asStateFlow()

    // Scan State
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _currentResult = MutableStateFlow<PhishingAnalysisResult?>(null)
    val currentResult: StateFlow<PhishingAnalysisResult?> = _currentResult.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    // History and Whitelist
    val scanHistory: StateFlow<List<ScanHistoryEntity>> = scanHistoryDao.getAllScans()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val whitelistDomains: StateFlow<List<WhitelistEntity>> = whitelistDao.getAllWhitelisted()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val totalScansCount: StateFlow<Int> = scanHistoryDao.getScanCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    val phishingDetectedCount: StateFlow<Int> = scanHistoryDao.getPhishingCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    // Threat Intelligence Feed Search & Filter
    private val _threatSearchQuery = MutableStateFlow("")
    val threatSearchQuery: StateFlow<String> = _threatSearchQuery.asStateFlow()

    private val _selectedThreatCategory = MutableStateFlow("ALL")
    val selectedThreatCategory: StateFlow<String> = _selectedThreatCategory.asStateFlow()

    val knownThreats: StateFlow<List<com.example.data.model.KnownPhishingThreat>> = kotlinx.coroutines.flow.combine(
        _threatSearchQuery,
        _selectedThreatCategory
    ) { query, category ->
        var list = com.example.data.model.ThreatDatabase.KNOWN_FAKE_WEBSITES
        if (category != "ALL") {
            list = list.filter { it.category.equals(category, ignoreCase = true) }
        }
        if (query.isNotBlank()) {
            val q = query.lowercase().trim()
            list = list.filter {
                it.title.lowercase().contains(q) ||
                it.fakeDomain.lowercase().contains(q) ||
                it.targetBrand.lowercase().contains(q) ||
                it.attackVector.lowercase().contains(q) ||
                it.category.lowercase().contains(q)
            }
        }
        list
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), com.example.data.model.ThreatDatabase.KNOWN_FAKE_WEBSITES)

    fun onThreatSearchQueryChange(query: String) {
        _threatSearchQuery.value = query
    }

    fun onThreatCategorySelect(category: String) {
        _selectedThreatCategory.value = category
    }

    fun loadThreatScenario(threat: com.example.data.model.KnownPhishingThreat) {
        _urlInput.value = threat.sampleUrl
        _contextInput.value = threat.sampleMessage
        _errorMessage.value = null
        _currentResult.value = null
    }

    val presets = listOf(
        PresetScenario(
            title = "India Post Smishing",
            category = "Postal Scam",
            url = "http://inddiapost-tracking.top/update-address",
            contextText = "India Post: Your package cannot be delivered due to incomplete address. Please update address within 24 hours at the link to avoid return.",
            description = "Typo-squatting (inddiapost), .top TLD, artificial 24h urgency, brand impersonation."
        ),
        PresetScenario(
            title = "MetaMask Seed Theft",
            category = "Crypto Drainer",
            url = "https://metamask-seedphrase-restore.link/validate-wallet",
            contextText = "MetaMask Security: Ethereum network upgrade requires mandatory wallet sync. Enter your 12-word Secret Recovery Phrase to prevent token loss.",
            description = "Web3 seed phrase theft, .link TLD, fake protocol upgrade."
        ),
        PresetScenario(
            title = "SBI Banking KYC Scam",
            category = "Banking",
            url = "http://sbi-yono-kyc-update.xyz/login.php",
            contextText = "Dear SBI customer, your YONO netbanking account will be blocked today within 24 hours. Click here to update your PAN card & Aadhaar KYC immediately.",
            description = "Hyphen stuffing, .xyz TLD, high pressure deadline, banking identity theft."
        ),
        PresetScenario(
            title = "Income Tax Refund Lure",
            category = "Tax / Gov",
            url = "http://incometax-refund-claim-portal.top/refund/claim",
            contextText = "Income Tax Alert: You have an approved tax refund of Rs 24,750 from AY 2025-26. Click here to confirm your bank account number and debit card.",
            description = "Tax refund greed trigger, fake government portal, unencrypted HTTP."
        ),
        PresetScenario(
            title = "PayPal Security Alert",
            category = "Financial",
            url = "https://secure-paypa1-verification.xyz/login/verify",
            contextText = "PayPal Security Alert: Unauthorized login attempt detected from Russia. Your account is suspended. Verify credentials immediately.",
            description = "Character substitution (paypa1), .xyz TLD, account panic tactics, brand impersonation."
        ),
        PresetScenario(
            title = "Windows Trojan Lock",
            category = "Scareware",
            url = "http://microsoft-defender-trojan-alert.cfd/warning.html",
            contextText = "CRITICAL ALERT: Windows Defender detected Trojan:Win32/Spyware.Banker on your device! Your system is locked. Call Microsoft Helpline immediately.",
            description = "Scareware screen lock, .cfd TLD, toll-free call center fraud."
        ),
        PresetScenario(
            title = "Instagram Blue Badge",
            category = "Social Media",
            url = "https://instagram-bluebadge-meta.top/apply-verification",
            contextText = "Instagram Creator Program: Your profile is eligible for free Blue Verification Badge. Fill in your login credentials to receive verified tick.",
            description = "Status / ego lure, credential harvesting, unauthorized host."
        ),
        PresetScenario(
            title = "Netflix Payment Failed",
            category = "Subscription",
            url = "http://netflix-billing-update.club/account",
            contextText = "Netflix: We were unable to process your payment for the next billing cycle. Your membership is on hold. Update payment info now.",
            description = "Hyphen stuffing, .club TLD, fake urgency to steal credit card details."
        ),
        PresetScenario(
            title = "Official SBI (.bank.in)",
            category = "Verified Safe",
            url = "https://sbi.bank.in/portal/web/home",
            contextText = "State Bank of India official secure internet banking portal under RBI .bank.in registry.",
            description = "RBI restricted .bank.in domain, official institution, verified safe."
        ),
        PresetScenario(
            title = "Legitimate India Post",
            category = "Verified Safe",
            url = "https://www.indiapost.gov.in/VAS/Pages/trackconsignment.aspx",
            contextText = "Track your speed post consignment on the official India Post portal.",
            description = "Official .gov.in domain, HTTPS, present in verified SQL whitelist."
        ),
        PresetScenario(
            title = "Official Google Login",
            category = "Verified Safe",
            url = "https://accounts.google.com/signin/v2/identifier",
            contextText = "Sign in to your Google Account with your email and password.",
            description = "Official Google Accounts portal, high reputation, whitelist matched."
        )
    )

    fun onUrlChange(newUrl: String) {
        _urlInput.value = newUrl
        _errorMessage.value = null
    }

    fun onContextChange(newContext: String) {
        _contextInput.value = newContext
        _errorMessage.value = null
    }

    fun loadPreset(preset: PresetScenario) {
        _urlInput.value = preset.url
        _contextInput.value = preset.contextText
        _errorMessage.value = null
        _currentResult.value = null
    }

    fun clearInput() {
        _urlInput.value = ""
        _contextInput.value = ""
        _errorMessage.value = null
        _currentResult.value = null
    }

    fun analyze() {
        val url = _urlInput.value.trim()
        if (url.isBlank()) {
            _errorMessage.value = "Please enter a valid URL to scan"
            return
        }

        viewModelScope.launch {
            _isScanning.value = true
            _errorMessage.value = null
            try {
                val result = engine.analyze(url, _contextInput.value)
                _currentResult.value = result

                // Save to Room DB
                val threatsJson = stringListAdapter.toJson(result.detectedThreats)
                val entity = ScanHistoryEntity(
                    url = result.url,
                    contextText = result.contextText,
                    status = result.status,
                    riskScore = result.riskScore,
                    detectedThreatsJson = threatsJson,
                    urlStructureBreakdown = result.analysisBreakdown.urlStructure,
                    nlpUrgencyBreakdown = result.analysisBreakdown.nlpUrgencyCheck,
                    brandImpersonationBreakdown = result.analysisBreakdown.brandImpersonation,
                    whitelistStatus = result.analysisBreakdown.whitelistStatus,
                    userExplanation = result.userExplanation,
                    rawJson = result.rawJson,
                    scannedAt = result.scannedAt
                )
                scanHistoryDao.insertScan(entity)

            } catch (e: Exception) {
                _errorMessage.value = "Analysis failed: ${e.localizedMessage ?: "Unknown error"}"
            } finally {
                _isScanning.value = false
            }
        }
    }

    fun loadHistoryItem(entity: ScanHistoryEntity) {
        val threatsList = try {
            stringListAdapter.fromJson(entity.detectedThreatsJson) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }

        val result = PhishingAnalysisResult(
            url = entity.url,
            status = entity.status,
            riskScore = entity.riskScore,
            detectedThreats = threatsList,
            analysisBreakdown = AnalysisBreakdown(
                urlStructure = entity.urlStructureBreakdown,
                nlpUrgencyCheck = entity.nlpUrgencyBreakdown,
                brandImpersonation = entity.brandImpersonationBreakdown,
                whitelistStatus = entity.whitelistStatus
            ),
            userExplanation = entity.userExplanation,
            rawJson = entity.rawJson,
            scannedAt = entity.scannedAt,
            contextText = entity.contextText
        )
        _urlInput.value = entity.url
        _contextInput.value = entity.contextText
        _currentResult.value = result
    }

    fun deleteHistoryItem(id: Long) {
        viewModelScope.launch {
            scanHistoryDao.deleteScanById(id)
        }
    }

    fun clearAllHistory() {
        viewModelScope.launch {
            scanHistoryDao.clearAll()
        }
    }

    fun addCustomWhitelistDomain(domain: String, brand: String, category: String) {
        val cleanDomain = domain.trim().lowercase().removePrefix("http://").removePrefix("https://").removePrefix("www.")
        if (cleanDomain.isNotBlank()) {
            viewModelScope.launch {
                whitelistDao.insert(
                    WhitelistEntity(
                        domain = cleanDomain,
                        brandName = brand.ifBlank { cleanDomain },
                        category = category.ifBlank { "Custom" },
                        isVerified = true
                    )
                )
            }
        }
    }

    fun deleteWhitelistDomain(id: Long) {
        viewModelScope.launch {
            whitelistDao.deleteById(id)
        }
    }
}
