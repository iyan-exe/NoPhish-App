package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import com.example.data.model.ScanHistoryEntity
import com.example.data.model.WhitelistEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Database(
    entities = [ScanHistoryEntity::class, WhitelistEntity::class],
    version = 1,
    exportSchema = false
)
abstract class PhishShieldDatabase : RoomDatabase() {
    abstract fun scanHistoryDao(): ScanHistoryDao
    abstract fun whitelistDao(): WhitelistDao

    companion object {
        @Volatile
        private var INSTANCE: PhishShieldDatabase? = null

        fun getDatabase(context: Context): PhishShieldDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PhishShieldDatabase::class.java,
                    "phish_shield_db"
                ).addCallback(object : Callback() {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        super.onCreate(db)
                        CoroutineScope(Dispatchers.IO).launch {
                            INSTANCE?.whitelistDao()?.insertAll(defaultWhitelist)
                        }
                    }
                }).build()
                INSTANCE = instance
                instance
            }
        }

        val defaultWhitelist = listOf(
            // Indian Banking Authorities & Apex Regulators
            WhitelistEntity(domain = "rbi.org.in", brandName = "Reserve Bank of India (RBI)", category = "Banking Authority"),
            WhitelistEntity(domain = "npci.org.in", brandName = "National Payments Corporation of India (NPCI)", category = "Financial Infrastructure"),
            WhitelistEntity(domain = "bhimupi.org.in", brandName = "BHIM UPI", category = "Financial Infrastructure"),
            WhitelistEntity(domain = "idrbt.ac.in", brandName = "IDRBT Banking Technology", category = "Banking Infrastructure"),
            WhitelistEntity(domain = "sebi.gov.in", brandName = "SEBI", category = "Regulatory Authority"),
            WhitelistEntity(domain = "incometax.gov.in", brandName = "Income Tax Department India", category = "Government"),
            WhitelistEntity(domain = "uidai.gov.in", brandName = "UIDAI Aadhaar", category = "Government"),
            WhitelistEntity(domain = "indiapost.gov.in", brandName = "India Post", category = "Government"),
            WhitelistEntity(domain = "ippbonline.com", brandName = "India Post Payments Bank", category = "Financial"),

            // State Bank of India (SBI) - .bank.in, .sbi, .co.in, .com
            WhitelistEntity(domain = "sbi.bank.in", brandName = "State Bank of India (SBI)", category = "Financial"),
            WhitelistEntity(domain = "onlinesbi.sbi.bank.in", brandName = "SBI Internet Banking", category = "Financial"),
            WhitelistEntity(domain = "sbi.sbi", brandName = "State Bank of India (.sbi)", category = "Financial"),
            WhitelistEntity(domain = "onlinesbi.sbi", brandName = "Online SBI (.sbi)", category = "Financial"),
            WhitelistEntity(domain = "bank.sbi", brandName = "SBI Corporate Portal", category = "Financial"),
            WhitelistEntity(domain = "yono.sbi", brandName = "SBI YONO Official", category = "Financial"),
            WhitelistEntity(domain = "sbi.co.in", brandName = "State Bank of India (SBI)", category = "Financial"),
            WhitelistEntity(domain = "onlinesbi.com", brandName = "Online SBI", category = "Financial"),
            WhitelistEntity(domain = "sbicard.com", brandName = "SBI Card", category = "Financial"),

            // HDFC Bank
            WhitelistEntity(domain = "hdfc.bank.in", brandName = "HDFC Bank (.bank.in)", category = "Financial"),
            WhitelistEntity(domain = "hdfcbank.com", brandName = "HDFC Bank", category = "Financial"),
            WhitelistEntity(domain = "netbanking.hdfcbank.com", brandName = "HDFC NetBanking", category = "Financial"),
            WhitelistEntity(domain = "hdfc.com", brandName = "HDFC Portal", category = "Financial"),

            // ICICI Bank
            WhitelistEntity(domain = "icici.bank.in", brandName = "ICICI Bank (.bank.in)", category = "Financial"),
            WhitelistEntity(domain = "icicibank.com", brandName = "ICICI Bank", category = "Financial"),
            WhitelistEntity(domain = "infinity.icicibank.com", brandName = "ICICI Infinity Banking", category = "Financial"),

            // Punjab National Bank (PNB)
            WhitelistEntity(domain = "pnb.bank.in", brandName = "Punjab National Bank (PNB)", category = "Financial"),
            WhitelistEntity(domain = "pnbindia.in", brandName = "Punjab National Bank", category = "Financial"),
            WhitelistEntity(domain = "netpnb.com", brandName = "PNB Internet Banking", category = "Financial"),

            // Bank of Baroda
            WhitelistEntity(domain = "bankofbaroda.bank.in", brandName = "Bank of Baroda (.bank.in)", category = "Financial"),
            WhitelistEntity(domain = "bankofbaroda.in", brandName = "Bank of Baroda", category = "Financial"),
            WhitelistEntity(domain = "bankofbaroda.com", brandName = "Bank of Baroda", category = "Financial"),
            WhitelistEntity(domain = "bobibanking.com", brandName = "Bank of Baroda NetBanking", category = "Financial"),

            // Axis Bank
            WhitelistEntity(domain = "axis.bank.in", brandName = "Axis Bank (.bank.in)", category = "Financial"),
            WhitelistEntity(domain = "axisbank.com", brandName = "Axis Bank", category = "Financial"),
            WhitelistEntity(domain = "axisbank.co.in", brandName = "Axis Bank", category = "Financial"),

            // Kotak Mahindra Bank
            WhitelistEntity(domain = "kotak.bank.in", brandName = "Kotak Mahindra Bank (.bank.in)", category = "Financial"),
            WhitelistEntity(domain = "kotak.com", brandName = "Kotak Mahindra Bank", category = "Financial"),

            // Canara Bank
            WhitelistEntity(domain = "canarabank.bank.in", brandName = "Canara Bank (.bank.in)", category = "Financial"),
            WhitelistEntity(domain = "canarabank.com", brandName = "Canara Bank", category = "Financial"),

            // IndusInd Bank
            WhitelistEntity(domain = "indusind.bank.in", brandName = "IndusInd Bank (.bank.in)", category = "Financial"),
            WhitelistEntity(domain = "indusind.com", brandName = "IndusInd Bank", category = "Financial"),

            // Union Bank of India
            WhitelistEntity(domain = "unionbankofindia.bank.in", brandName = "Union Bank of India", category = "Financial"),
            WhitelistEntity(domain = "unionbankonline.bank.in", brandName = "Union Bank Internet Banking", category = "Financial"),
            WhitelistEntity(domain = "unionbankofindia.co.in", brandName = "Union Bank of India", category = "Financial"),

            // Bank of India
            WhitelistEntity(domain = "bankofindia.bank.in", brandName = "Bank of India", category = "Financial"),
            WhitelistEntity(domain = "bankofindia.co.in", brandName = "Bank of India", category = "Financial"),

            // IDBI & Indian Bank & Central Bank & UCO
            WhitelistEntity(domain = "idbi.bank.in", brandName = "IDBI Bank", category = "Financial"),
            WhitelistEntity(domain = "indianbank.bank.in", brandName = "Indian Bank", category = "Financial"),
            WhitelistEntity(domain = "centralbank.bank.in", brandName = "Central Bank of India", category = "Financial"),
            WhitelistEntity(domain = "uco.bank.in", brandName = "UCO Bank", category = "Financial"),

            // Yes Bank, Federal Bank, IDFC FIRST
            WhitelistEntity(domain = "yes.bank.in", brandName = "Yes Bank", category = "Financial"),
            WhitelistEntity(domain = "federal.bank.in", brandName = "Federal Bank", category = "Financial"),
            WhitelistEntity(domain = "idfcfirst.bank.in", brandName = "IDFC FIRST Bank", category = "Financial"),
            WhitelistEntity(domain = "idfcfirstbank.com", brandName = "IDFC FIRST Bank", category = "Financial"),

            // Payments Banks
            WhitelistEntity(domain = "paytm.bank.in", brandName = "Paytm Payments Bank", category = "Fintech"),
            WhitelistEntity(domain = "paytmbank.com", brandName = "Paytm Payments Bank", category = "Fintech"),
            WhitelistEntity(domain = "airtelpayments.bank.in", brandName = "Airtel Payments Bank", category = "Fintech"),
            WhitelistEntity(domain = "airtelbank.com", brandName = "Airtel Payments Bank", category = "Fintech"),

            // Global Technology & Cloud Authorities
            WhitelistEntity(domain = "google.com", brandName = "Google", category = "Technology"),
            WhitelistEntity(domain = "accounts.google.com", brandName = "Google Accounts", category = "Technology"),
            WhitelistEntity(domain = "youtube.com", brandName = "YouTube", category = "Technology"),
            WhitelistEntity(domain = "microsoft.com", brandName = "Microsoft", category = "Technology"),
            WhitelistEntity(domain = "login.microsoftonline.com", brandName = "Microsoft 365", category = "Technology"),
            WhitelistEntity(domain = "live.com", brandName = "Microsoft Live", category = "Technology"),
            WhitelistEntity(domain = "apple.com", brandName = "Apple", category = "Technology"),
            WhitelistEntity(domain = "icloud.com", brandName = "Apple iCloud", category = "Technology"),
            WhitelistEntity(domain = "amazon.com", brandName = "Amazon", category = "E-Commerce"),
            WhitelistEntity(domain = "amazon.in", brandName = "Amazon India", category = "E-Commerce"),
            WhitelistEntity(domain = "netflix.com", brandName = "Netflix", category = "Entertainment"),
            WhitelistEntity(domain = "github.com", brandName = "GitHub", category = "Technology"),
            WhitelistEntity(domain = "gitlab.com", brandName = "GitLab", category = "Technology"),
            WhitelistEntity(domain = "stackoverflow.com", brandName = "Stack Overflow", category = "Technology"),
            WhitelistEntity(domain = "wikipedia.org", brandName = "Wikipedia", category = "Education"),
            WhitelistEntity(domain = "openai.com", brandName = "OpenAI", category = "Technology"),
            WhitelistEntity(domain = "chatgpt.com", brandName = "ChatGPT", category = "Technology"),
            WhitelistEntity(domain = "spotify.com", brandName = "Spotify", category = "Entertainment"),
            WhitelistEntity(domain = "linkedin.com", brandName = "LinkedIn", category = "Social Media"),
            WhitelistEntity(domain = "facebook.com", brandName = "Facebook", category = "Social Media"),
            WhitelistEntity(domain = "instagram.com", brandName = "Instagram", category = "Social Media"),
            WhitelistEntity(domain = "whatsapp.com", brandName = "WhatsApp", category = "Social Media"),
            WhitelistEntity(domain = "twitter.com", brandName = "Twitter", category = "Social Media"),
            WhitelistEntity(domain = "x.com", brandName = "X / Twitter", category = "Social Media"),
            WhitelistEntity(domain = "reddit.com", brandName = "Reddit", category = "Social Media"),

            // Global Financial Giants
            WhitelistEntity(domain = "paypal.com", brandName = "PayPal", category = "Financial"),
            WhitelistEntity(domain = "stripe.com", brandName = "Stripe", category = "Financial"),
            WhitelistEntity(domain = "chase.com", brandName = "Chase Bank", category = "Financial"),
            WhitelistEntity(domain = "bankofamerica.com", brandName = "Bank of America", category = "Financial"),
            WhitelistEntity(domain = "wellsfargo.com", brandName = "Wells Fargo", category = "Financial"),
            WhitelistEntity(domain = "citi.com", brandName = "Citibank", category = "Financial"),

            // Logistics & Media
            WhitelistEntity(domain = "usps.com", brandName = "USPS", category = "Government / Logistics"),
            WhitelistEntity(domain = "dhl.com", brandName = "DHL Express", category = "Logistics"),
            WhitelistEntity(domain = "fedex.com", brandName = "FedEx", category = "Logistics"),
            WhitelistEntity(domain = "ups.com", brandName = "UPS", category = "Logistics"),
            WhitelistEntity(domain = "medium.com", brandName = "Medium", category = "Media"),
            WhitelistEntity(domain = "nytimes.com", brandName = "The New York Times", category = "News"),
            WhitelistEntity(domain = "bbc.com", brandName = "BBC News", category = "News")
        )
    }
}
