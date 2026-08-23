package com.example.data.model

data class KnownPhishingThreat(
    val id: String,
    val title: String,
    val category: String, // "Banking", "Smishing / Postal", "Crypto / Web3", "Social Media", "Tax / Gov", "Scareware", "E-Commerce"
    val targetBrand: String,
    val fakeDomain: String,
    val sampleUrl: String,
    val sampleMessage: String,
    val riskScore: Int,
    val attackVector: String,
    val indicatorsOfCompromise: List<String>,
    val deceptionTechnique: String
)

object ThreatDatabase {

    val THREAT_CATEGORIES = listOf(
        "ALL",
        "Banking",
        "Smishing / Postal",
        "Crypto / Web3",
        "Social Media",
        "Tax / Gov",
        "Scareware",
        "E-Commerce"
    )

    val KNOWN_FAKE_WEBSITES: List<KnownPhishingThreat> = listOf(
        // ------------------ 1. Banking & NetBanking Spoofs ------------------
        KnownPhishingThreat(
            id = "bank_sbi_yono",
            title = "SBI YONO Account Block Scam",
            category = "Banking",
            targetBrand = "State Bank of India (SBI)",
            fakeDomain = "sbi-yono-kyc-update.xyz",
            sampleUrl = "http://sbi-yono-kyc-update.xyz/login.php",
            sampleMessage = "Dear SBI customer, your YONO netbanking account will be blocked today within 24 hours. Click here to update your PAN card & Aadhaar KYC immediately.",
            riskScore = 98,
            attackVector = "Credential Harvesting & Banking OTP Interception",
            indicatorsOfCompromise = listOf(
                "Untrusted .xyz generic TLD",
                "Unauthorized non-banking domain (official is sbi.bank.in / onlinesbi.sbi)",
                "Urgency deadline trigger ('within 24 hours')",
                "Unencrypted HTTP protocol"
            ),
            deceptionTechnique = "Hyphen-stuffed brand keyword targeting panic of sudden bank account closure."
        ),
        KnownPhishingThreat(
            id = "bank_hdfc_reward",
            title = "HDFC NetBanking Reward Points Lure",
            category = "Banking",
            targetBrand = "HDFC Bank",
            fakeDomain = "hdfcbank-reward-redeem.top",
            sampleUrl = "https://hdfcbank-reward-redeem.top/auth/verify",
            sampleMessage = "Congratulations HDFC user! Your accumulated reward points worth Rs 8,450 will expire tonight. Redeem now into your bank account at the link.",
            riskScore = 95,
            attackVector = "NetBanking Password & Debit Card PIN Theft",
            indicatorsOfCompromise = listOf(
                "High-abuse .top top-level domain",
                "Brand spoofing without authorized .bank.in registry",
                "Financial greed trigger with tight expiry deadline",
                "Phishing keyword tokens in domain path ('auth', 'verify')"
            ),
            deceptionTechnique = "Greed lure combined with official brand keyword embedding."
        ),
        KnownPhishingThreat(
            id = "bank_icici_ip",
            title = "ICICI iMobile Raw IP Harvesting",
            category = "Banking",
            targetBrand = "ICICI Bank",
            fakeDomain = "103.25.12.88",
            sampleUrl = "http://103.25.12.88/icici/verify-kyc.html",
            sampleMessage = "ICICI Bank: Critical update! Your iMobile banking access is restricted due to pending KYC documents. Verify your details now.",
            riskScore = 99,
            attackVector = "Direct Raw IP Credential Capture",
            indicatorsOfCompromise = listOf(
                "Raw numerical IP host (103.25.12.88) evading domain reputation filters",
                "Insecure HTTP connection",
                "Brand keyword stuffing in URL path",
                "High-pressure account restriction notice"
            ),
            deceptionTechnique = "Hosting malicious phishing kit directly on unindexed cloud VPS IP address."
        ),
        KnownPhishingThreat(
            id = "bank_pnb_blocked",
            title = "PNB One Urgent KYC Mandatory",
            category = "Banking",
            targetBrand = "Punjab National Bank (PNB)",
            fakeDomain = "pnb-secure-login.buzz",
            sampleUrl = "https://pnb-secure-login.buzz/netbanking/login",
            sampleMessage = "PNB Alert: Your PNB One account has failed annual verification. Complete re-KYC within 12 hours or card will be permanently disabled.",
            riskScore = 96,
            attackVector = "NetBanking Login & MPIN Harvesting",
            indicatorsOfCompromise = listOf(
                "High-risk .buzz TLD",
                "Hyphenated brand spoofing (pnb-secure-login)",
                "Consequence threat pressure ('permanently disabled')",
                "Fake SSL certificate on unauthorized host"
            ),
            deceptionTechnique = "Security scare tactic threatening card deactivation."
        ),
        KnownPhishingThreat(
            id = "bank_chase_wire",
            title = "Chase Bank Unauthorized Wire Fraud",
            category = "Banking",
            targetBrand = "Chase Bank",
            fakeDomain = "chase-bank-unauthorized-access.cfd",
            sampleUrl = "https://chase-bank-unauthorized-access.cfd/verify-security",
            sampleMessage = "Chase Security: An unauthorized wire transfer of $2,480.00 to overseas account was initiated. If this was NOT you, cancel transaction immediately.",
            riskScore = 97,
            attackVector = "Online Banking Session Hijacking",
            indicatorsOfCompromise = listOf(
                "Abuse-prone .cfd TLD",
                "Multi-word hyphen stuffing in domain",
                "Fake fraud alert panic induction",
                "Unauthorized host (official is chase.com)"
            ),
            deceptionTechnique = "Reverse psychological panic inducing user to 'cancel' a fictitious transaction."
        ),
        KnownPhishingThreat(
            id = "bank_bofa_2fa",
            title = "Bank of America 2FA Intercept",
            category = "Banking",
            targetBrand = "Bank of America",
            fakeDomain = "secure-bofa-online-auth.live",
            sampleUrl = "http://secure-bofa-online-auth.live/sign-in",
            sampleMessage = "Bank of America: We detected a new login from Moscow, Russia. Please sign in now to verify your trusted device.",
            riskScore = 98,
            attackVector = "Real-time Reverse Proxy (AitM) 2FA Theft",
            indicatorsOfCompromise = listOf(
                "Insecure HTTP protocol",
                "Hyphen-stuffed domain on .live TLD",
                "Geographic scare tactic ('login from Russia')",
                "Spoof of brand abbreviation 'bofa'"
            ),
            deceptionTechnique = "Adversary-in-the-Middle reverse proxy capturing session cookies."
        ),
        KnownPhishingThreat(
            id = "bank_paytm_kyc",
            title = "Paytm Wallet Deactivation Warning",
            category = "Banking",
            targetBrand = "Paytm Payments Bank",
            fakeDomain = "paytm-wallet-kyc-update.vip",
            sampleUrl = "http://paytm-wallet-kyc-update.vip/update",
            sampleMessage = "Dear customer, your Paytm wallet will be deactivated today. Click link to complete video KYC and receive Rs 200 cashback.",
            riskScore = 95,
            attackVector = "UPI Passcode & Aadhaar Number Theft",
            indicatorsOfCompromise = listOf(
                "Untrusted .vip TLD",
                "Repetitive keyword stuffing ('paytm-wallet-kyc')",
                "Cashback bribe mixed with threat of deactivation",
                "Unauthorized domain"
            ),
            deceptionTechnique = "Carrot-and-stick psychological hook combining fear with financial reward."
        ),

        // ------------------ 2. Smishing & Postal Delivery Scams ------------------
        KnownPhishingThreat(
            id = "smish_indiapost_typo",
            title = "India Post Redelivery Smishing",
            category = "Smishing / Postal",
            targetBrand = "India Post",
            fakeDomain = "inddiapost-tracking.top",
            sampleUrl = "http://inddiapost-tracking.top/update-address",
            sampleMessage = "India Post: Your package cannot be delivered due to incomplete street number. Please update address within 24 hours to prevent return to sender.",
            riskScore = 99,
            attackVector = "Credit Card / Debit Card Micro-payment Theft",
            indicatorsOfCompromise = listOf(
                "Typosquatted domain ('inddiapost' with double 'd')",
                "High-risk .top TLD",
                "Postal delivery failure pretext ('incomplete address')",
                "24-hour return-to-sender deadline"
            ),
            deceptionTechnique = "Mass SMS smishing asking for Rs 25 redelivery charge to steal full card details."
        ),
        KnownPhishingThreat(
            id = "smish_usps_customs",
            title = "USPS Redelivery Notice Trap",
            category = "Smishing / Postal",
            targetBrand = "USPS",
            fakeDomain = "usps-redelivery-postal-customs.xyz",
            sampleUrl = "https://usps-redelivery-postal-customs.xyz/track/package",
            sampleMessage = "USPS: Package US951490119 has an unpaid customs charge of $1.85. Reschedule delivery today before package is returned to terminal.",
            riskScore = 98,
            attackVector = "Payment Card & Identity Theft",
            indicatorsOfCompromise = listOf(
                "Severe hyphen stuffing (4 hyphens)",
                ".xyz generic TLD",
                "Fake tracking number format",
                "Micro-fee payment lure ($1.85)"
            ),
            deceptionTechnique = "Low friction micro-payment ($1.85) lowering user guard to capture credit card numbers."
        ),
        KnownPhishingThreat(
            id = "smish_dhl_clearance",
            title = "DHL Express Customs Clearance Fee",
            category = "Smishing / Postal",
            targetBrand = "DHL",
            fakeDomain = "dhl-express-customs-clearance.icu",
            sampleUrl = "http://dhl-express-customs-clearance.icu/pay-duty",
            sampleMessage = "DHL Express: Your shipment is held at central customs hub due to pending duty of $4.20. Pay duty now to release parcel for dispatch.",
            riskScore = 97,
            attackVector = "Card Details & Personal Address Harvesting",
            indicatorsOfCompromise = listOf(
                "Abuse TLD (.icu)",
                "Insecure HTTP protocol",
                "Customs duty pending lure",
                "Unauthorized domain (official is dhl.com)"
            ),
            deceptionTechnique = "Impersonating international parcel courier with urgent customs hold pretext."
        ),
        KnownPhishingThreat(
            id = "smish_fedex_exception",
            title = "FedEx Shipment Exception Notice",
            category = "Smishing / Postal",
            targetBrand = "FedEx",
            fakeDomain = "fedex-package-exception.buzz",
            sampleUrl = "https://fedex-package-exception.buzz/reschedule-delivery",
            sampleMessage = "FedEx: Delivery attempt failed for parcel #FDX-88402. Recipient absent. Confirm delivery location and reschedule within 48 hours.",
            riskScore = 96,
            attackVector = "Credential & Banking Theft",
            indicatorsOfCompromise = listOf(
                "High-risk .buzz TLD",
                "Hyphen-stuffed brand keyword",
                "Delivery failure pretext",
                "Unauthorized host"
            ),
            deceptionTechnique = "Mimicking real FedEx tracking UI to prompt for personal address & payment."
        ),
        KnownPhishingThreat(
            id = "smish_royalmail_duty",
            title = "Royal Mail Surcharge Scam",
            category = "Smishing / Postal",
            targetBrand = "Royal Mail",
            fakeDomain = "royalmail-fee-redelivery.cc",
            sampleUrl = "http://royalmail-fee-redelivery.cc/portal/pay",
            sampleMessage = "Royal Mail: A parcel for you has a £2.99 unpaid shipping fee. Please pay online within 24h to avoid parcel return.",
            riskScore = 96,
            attackVector = "UK Bank Debit Card Harvesting",
            indicatorsOfCompromise = listOf(
                ".cc legacy spam TLD",
                "Micro-surcharge pretext (£2.99)",
                "Artificial 24h urgency",
                "Unencrypted HTTP transmission"
            ),
            deceptionTechnique = "UK nationwide smishing wave targeting online shopping deliveries."
        ),

        // ------------------ 3. Web3 & Crypto Wallet Drainers ------------------
        KnownPhishingThreat(
            id = "crypto_metamask_seed",
            title = "MetaMask Seed Phrase Validator",
            category = "Crypto / Web3",
            targetBrand = "MetaMask",
            fakeDomain = "metamask-seedphrase-restore.link",
            sampleUrl = "https://metamask-seedphrase-restore.link/validate-wallet",
            sampleMessage = "MetaMask Security: Ethereum network upgrade requires mandatory wallet sync. Enter your 12-word Secret Recovery Phrase to prevent token loss.",
            riskScore = 100,
            attackVector = "Complete Crypto Wallet Asset Drain",
            indicatorsOfCompromise = listOf(
                "Explicit 12-word seed recovery phrase theft",
                "Deceptive .link TLD",
                "Network upgrade pretext",
                "Consequence threat of token loss"
            ),
            deceptionTechnique = "Direct extraction of private keys granting total access to all blockchain assets."
        ),
        KnownPhishingThreat(
            id = "crypto_trustwallet_drainer",
            title = "Trust Wallet Airdrop Permit Drainer",
            category = "Crypto / Web3",
            targetBrand = "Trust Wallet",
            fakeDomain = "trustwallet-airdrop-claim.click",
            sampleUrl = "https://trustwallet-airdrop-claim.click/connect-wallet",
            sampleMessage = "Exclusive Trust Wallet 50,000 TWT Airdrop! Connect your Web3 wallet and sign transaction to claim $2,500 in tokens immediately.",
            riskScore = 99,
            attackVector = "Malicious Permit2 / SetApprovalForAll Smart Contract Drainer",
            indicatorsOfCompromise = listOf(
                "High-risk .click TLD",
                "Unrealistic high-value airdrop bait ($2,500)",
                "Web3 wallet connection hook",
                "Zero-cost token grant lure"
            ),
            deceptionTechnique = "Tricking user into signing an unlimited ERC-20 / NFT approval allowing hacker to sweep wallet."
        ),
        KnownPhishingThreat(
            id = "crypto_binance_security",
            title = "Binance Account Lockdown Alert",
            category = "Crypto / Web3",
            targetBrand = "Binance",
            fakeDomain = "binance-login-security-check.top",
            sampleUrl = "https://binance-login-security-check.top/auth/verify-ip",
            sampleMessage = "Binance: Unauthorized IP login attempt from Hong Kong. All withdrawals suspended. Log in now to cancel withdrawal and secure 2FA.",
            riskScore = 98,
            attackVector = "Exchange Account Takeover & API Key Harvesting",
            indicatorsOfCompromise = listOf(
                "High-abuse .top TLD",
                "Withdrawal suspension panic trigger",
                "Fake IP geolocation lure",
                "Unauthorized domain (official is binance.com)"
            ),
            deceptionTechnique = "Scaring crypto traders with withdrawal lock threats."
        ),
        KnownPhishingThreat(
            id = "crypto_phantom_solana",
            title = "Phantom Solana Airdrop Drainer",
            category = "Crypto / Web3",
            targetBrand = "Phantom Wallet",
            fakeDomain = "phantom-solana-bonus-claim.vip",
            sampleUrl = "https://phantom-solana-bonus-claim.vip/claim-sol",
            sampleMessage = "Solana Foundation Reward: Claim 25 Free SOL allocated to active wallet addresses. Connect Phantom wallet and sign verification.",
            riskScore = 99,
            attackVector = "Solana Wallet Draining & Token Sweeping",
            indicatorsOfCompromise = listOf(
                "Untrusted .vip TLD",
                "Free SOL token bait",
                "Fake Foundation sponsorship",
                "Malicious transaction signature prompt"
            ),
            deceptionTechnique = "Solana dApp spoof that injects malicious transfer instruction."
        ),

        // ------------------ 4. Social Media & Account Hijacking ------------------
        KnownPhishingThreat(
            id = "social_instagram_blue",
            title = "Instagram Verified Badge Form",
            category = "Social Media",
            targetBrand = "Instagram / Meta",
            fakeDomain = "instagram-bluebadge-meta.top",
            sampleUrl = "https://instagram-bluebadge-meta.top/apply-verification",
            sampleMessage = "Instagram Creator Program: Your profile is eligible for free Blue Verification Badge. Fill in your login credentials to receive verified tick.",
            riskScore = 97,
            attackVector = "Account Hijacking for Ransom & Scam Broadcasting",
            indicatorsOfCompromise = listOf(
                "High-abuse .top TLD",
                "Ego / status bait (Blue Verified Tick)",
                "Password harvesting on third-party domain",
                "Unauthorized domain"
            ),
            deceptionTechnique = "Targeting creators and influencers eager for verified status."
        ),
        KnownPhishingThreat(
            id = "social_meta_copyright",
            title = "Meta Copyright Strike Deletion",
            category = "Social Media",
            targetBrand = "Meta / Facebook",
            fakeDomain = "meta-copyright-strike-appeal.xyz",
            sampleUrl = "https://meta-copyright-strike-appeal.xyz/case-review-id849",
            sampleMessage = "Meta Support Notice: We received copyright infringement reports against your page. Your page will be permanently deleted in 24 hours. Submit appeal now.",
            riskScore = 98,
            attackVector = "Business Manager Admin Account Takeover",
            indicatorsOfCompromise = listOf(
                "Generic .xyz TLD",
                "Permanent account deletion threat",
                "24-hour artificial appeal window",
                "Unauthorized host"
            ),
            deceptionTechnique = "Targeting business page owners who fear losing their customer base and followers."
        ),
        KnownPhishingThreat(
            id = "social_discord_nitro",
            title = "Discord Nitro 3 Months Free",
            category = "Social Media",
            targetBrand = "Discord",
            fakeDomain = "discord-nitro-gift-claim.shop",
            sampleUrl = "https://discord-nitro-gift-claim.shop/nitro/gift",
            sampleMessage = "Discord Promo: Valve and Steam partnered to give everyone 3 months of free Discord Nitro! Claim your gift before offer ends.",
            riskScore = 96,
            attackVector = "Discord Token Theft & Worm Propagation",
            indicatorsOfCompromise = listOf(
                ".shop generic TLD",
                "Free Nitro subscription bait",
                "Fake partner cross-promotion",
                "Unauthorized domain"
            ),
            deceptionTechnique = "Spammed through hacked friend accounts on Discord DMs to lure gamers."
        ),
        KnownPhishingThreat(
            id = "social_telegram_premium",
            title = "Telegram Web QR Code Hijack",
            category = "Social Media",
            targetBrand = "Telegram",
            fakeDomain = "telegram-premium-gift.club",
            sampleUrl = "https://telegram-premium-gift.club/login-qr",
            sampleMessage = "You have received a Telegram Premium Gift for 1 year! Scan the QR code or enter phone number OTP to activate subscription.",
            riskScore = 97,
            attackVector = "Session QR Hijacking (QRLJacking)",
            indicatorsOfCompromise = listOf(
                "High-abuse .club TLD",
                "Free 1-year premium bait",
                "QR code scanning / OTP theft prompt",
                "Unauthorized domain"
            ),
            deceptionTechnique = "Presenting the hacker's own Web session QR code for the victim to authorize."
        ),

        // ------------------ 5. Government, Tax & Subsidy Scams ------------------
        KnownPhishingThreat(
            id = "gov_incometax_refund",
            title = "Income Tax Department Refund Portal",
            category = "Tax / Gov",
            targetBrand = "Income Tax Department India",
            fakeDomain = "incometax-refund-claim-portal.top",
            sampleUrl = "http://incometax-refund-claim-portal.top/refund/claim",
            sampleMessage = "Income Tax Alert: You have an approved tax refund of Rs 24,750 from AY 2025-26. Click here to confirm your bank account number and debit card.",
            riskScore = 99,
            attackVector = "Bank Account Takeover & Card Expiry / CVV Theft",
            indicatorsOfCompromise = listOf(
                "Untrusted .top TLD instead of official .gov.in",
                "Insecure HTTP protocol",
                "Tax refund financial bait (Rs 24,750)",
                "Debit card number & CVV prompt for 'refund deposit'"
            ),
            deceptionTechnique = "Impersonating government tax authority during seasonal tax filing periods."
        ),
        KnownPhishingThreat(
            id = "gov_irs_stimulus",
            title = "IRS Federal Relief Payment Direct Deposit",
            category = "Tax / Gov",
            targetBrand = "Internal Revenue Service (IRS)",
            fakeDomain = "irs-tax-stimulus-payment.xyz",
            sampleUrl = "https://irs-tax-stimulus-payment.xyz/claim-benefit",
            sampleMessage = "Internal Revenue Service: You are eligible for an inflation relief payment of $1,400. Update direct deposit details immediately.",
            riskScore = 98,
            attackVector = "Social Security Number (SSN) & Routing Number Theft",
            indicatorsOfCompromise = listOf(
                ".xyz generic TLD (official is irs.gov)",
                "Hyphen-stuffed domain",
                "Government grant / subsidy bait ($1,400)",
                "Harvesting SSN and date of birth"
            ),
            deceptionTechnique = "Exploiting economic stimulus news to harvest full identity packages."
        ),
        KnownPhishingThreat(
            id = "gov_uidai_pan_link",
            title = "UIDAI Aadhaar PAN Mandatory Link",
            category = "Tax / Gov",
            targetBrand = "UIDAI / Aadhaar",
            fakeDomain = "uidai-aadhaar-pan-link.sbs",
            sampleUrl = "http://uidai-aadhaar-pan-link.sbs/link-portal",
            sampleMessage = "Govt Alert: Your PAN card will become inoperative in 24 hours due to non-linkage with Aadhaar. Pay Rs 50 penalty and link online now.",
            riskScore = 97,
            attackVector = "Identity Theft & Banking Micro-Fraud",
            indicatorsOfCompromise = listOf(
                "High-risk .sbs TLD",
                "Insecure HTTP protocol",
                "Government penalty intimidation",
                "Unauthorized host (official is uidai.gov.in)"
            ),
            deceptionTechnique = "Exploiting regulatory compliance anxiety regarding PAN-Aadhaar linking."
        ),
        KnownPhishingThreat(
            id = "gov_epfo_uan",
            title = "EPFO Provident Fund Balance Advance",
            category = "Tax / Gov",
            targetBrand = "EPFO",
            fakeDomain = "epfo-pf-balance-advance.online",
            sampleUrl = "http://epfo-pf-balance-advance.online/uan-login",
            sampleMessage = "EPFO Notice: 100% PF withdrawal advance approved under special relief scheme. Enter UAN number, password, and Aadhaar OTP to disburse funds.",
            riskScore = 96,
            attackVector = "Retirement Fund Hijacking & Identity Theft",
            indicatorsOfCompromise = listOf(
                "Untrusted .online generic TLD",
                "Insecure HTTP connection",
                "Unauthorized non-government host",
                "EPFO UAN password & OTP interception"
            ),
            deceptionTechnique = "Targeting salaried employees with promise of instant PF disbursal."
        ),

        // ------------------ 6. Scareware & Tech Support Fraud ------------------
        KnownPhishingThreat(
            id = "scare_defender_trojan",
            title = "Windows Defender Critical Trojan Lock",
            category = "Scareware",
            targetBrand = "Microsoft Defender",
            fakeDomain = "microsoft-defender-trojan-alert.cfd",
            sampleUrl = "http://microsoft-defender-trojan-alert.cfd/warning.html",
            sampleMessage = "CRITICAL ALERT: Windows Defender detected Trojan:Win32/Spyware.Banker on your device! Your system is locked. Call Microsoft Helpline immediately.",
            riskScore = 99,
            attackVector = "Remote Access Tool (AnyDesk/TeamViewer) Fraud",
            indicatorsOfCompromise = listOf(
                "Abuse-prone .cfd TLD",
                "Fake Trojan infection warning with browser fullscreen lock",
                "Toll-free phone number call prompt",
                "Unauthorized domain"
            ),
            deceptionTechnique = "Audio siren and flashing red screen creating overwhelming panic to make victim call scam call center."
        ),
        KnownPhishingThreat(
            id = "scare_mcafee_invoice",
            title = "McAfee Total Protection Auto-Renewal",
            category = "Scareware",
            targetBrand = "McAfee",
            fakeDomain = "mcafee-security-auto-renewal.shop",
            sampleUrl = "http://mcafee-security-auto-renewal.shop/invoice/cancel",
            sampleMessage = "Invoice Paid: $499.00 has been debited from your card for McAfee 3-Year Security. If you did not authorize this charge, click here to request instant refund.",
            riskScore = 96,
            attackVector = "Refund Scam & Bank Login Capture",
            indicatorsOfCompromise = listOf(
                ".shop generic TLD",
                "Fake $499 invoice receipt",
                "Reverse refund trap lure",
                "Insecure HTTP transmission"
            ),
            deceptionTechnique = "Fake invoice scaring victim into entering bank details under guise of 'canceling' a non-existent charge."
        ),
        KnownPhishingThreat(
            id = "scare_apple_icloud_lost",
            title = "Apple iCloud Lost iPhone Alert",
            category = "Scareware",
            targetBrand = "Apple iCloud",
            fakeDomain = "appleid-findmy-iphone-locate.top",
            sampleUrl = "https://appleid-findmy-iphone-locate.top/icloud/find",
            sampleMessage = "Find My iPhone: Your lost iPhone 15 Pro was turned on and location pinpointed near London. Log in with Apple ID to view live GPS coordinates.",
            riskScore = 98,
            attackVector = "Apple ID Credential & Device Passcode Theft (iCloud Unlock)",
            indicatorsOfCompromise = listOf(
                "High-abuse .top TLD",
                "Hyphen-stuffed brand keywords (appleid, findmy, iphone)",
                "Exploits hope of recovering stolen device",
                "Unauthorized host (official is icloud.com / apple.com)"
            ),
            deceptionTechnique = "Sent by phone thieves to victims of stolen iPhones to trick them into removing Activation Lock."
        ),

        // ------------------ 7. E-Commerce & Subscription Pretexts ------------------
        KnownPhishingThreat(
            id = "ecom_netflix_billing",
            title = "Netflix Membership On Hold",
            category = "E-Commerce",
            targetBrand = "Netflix",
            fakeDomain = "netflix-billing-update.club",
            sampleUrl = "http://netflix-billing-update.club/account/billing",
            sampleMessage = "Netflix: We were unable to process your payment for the next billing cycle. Your membership is on hold. Update payment info now to keep watching.",
            riskScore = 96,
            attackVector = "Credit Card Details & Billing Address Harvesting",
            indicatorsOfCompromise = listOf(
                "High-risk .club TLD",
                "Insecure HTTP protocol",
                "Account suspension / on-hold pretext",
                "Credit card input form on untrusted host"
            ),
            deceptionTechnique = "Mass emailing leveraging the massive popularity of streaming services."
        ),
        KnownPhishingThreat(
            id = "ecom_amazon_locked",
            title = "Amazon Prime Order Suspended",
            category = "E-Commerce",
            targetBrand = "Amazon",
            fakeDomain = "amazon-prime-order-verification.top",
            sampleUrl = "https://amazon-prime-order-verification.top/security/login",
            sampleMessage = "Amazon Security: Your high-value order #AMZ-99201 of Apple MacBook is on hold due to billing mismatch. Confirm billing info to proceed dispatch.",
            riskScore = 97,
            attackVector = "Amazon Account Takeover & Card Theft",
            indicatorsOfCompromise = listOf(
                "Untrusted .top TLD",
                "Hyphen-stuffed domain name",
                "High-value order pretext",
                "Unauthorized domain"
            ),
            deceptionTechnique = "Prompting user with fear of lost expensive order or fraud on their account."
        ),
        KnownPhishingThreat(
            id = "ecom_flipkart_spin",
            title = "Flipkart Big Billion Spin & Win",
            category = "E-Commerce",
            targetBrand = "Flipkart",
            fakeDomain = "flipkart-spin-win-reward.xyz",
            sampleUrl = "http://flipkart-spin-win-reward.xyz/spin/claim",
            sampleMessage = "Congratulations! You won a brand new iPhone 16 in Flipkart Big Billion Days lucky wheel! Pay Rs 99 delivery fee to ship your phone today.",
            riskScore = 98,
            attackVector = "Payment Gateway Phishing & Contact Harvesting",
            indicatorsOfCompromise = listOf(
                ".xyz generic TLD",
                "Unrealistic free iPhone prize hook",
                "Micro delivery fee trick (Rs 99)",
                "Viral WhatsApp share requirement"
            ),
            deceptionTechnique = "Viral survey scam asking users to share to 10 WhatsApp groups before stealing card info."
        ),
        KnownPhishingThreat(
            id = "ecom_shein_mystery",
            title = "Shein Free $500 Mystery Box",
            category = "E-Commerce",
            targetBrand = "Shein",
            fakeDomain = "shein-free-mystery-box.vip",
            sampleUrl = "https://shein-free-mystery-box.vip/reward/unboxing",
            sampleMessage = "Shein Summer Fest: You have been selected to receive a Free $500 Summer Wardrobe Mystery Box! Enter your shipping details and claim before timer runs out.",
            riskScore = 95,
            attackVector = "Recurring Hidden Subscription Scam & Card Capture",
            indicatorsOfCompromise = listOf(
                "Untrusted .vip TLD",
                "Free $500 goods lure",
                "Countdown timer pressure",
                "Unauthorized host"
            ),
            deceptionTechnique = "Signing victims up for hidden $79.99/month recurring charges under guise of free box."
        )
    )

    fun findMatchingThreat(cleanHost: String, fullUrl: String): KnownPhishingThreat? {
        val hostLower = cleanHost.lowercase().trim()
        val urlLower = fullUrl.lowercase().trim()

        return KNOWN_FAKE_WEBSITES.firstOrNull { threat ->
            val threatHost = threat.fakeDomain.lowercase()
            hostLower == threatHost ||
            hostLower.endsWith(".$threatHost") ||
            urlLower.contains(threatHost) ||
            (hostLower.contains(threat.targetBrand.lowercase().take(5)) && threat.indicatorsOfCompromise.any { hostLower.endsWith(it) })
        }
    }
}
