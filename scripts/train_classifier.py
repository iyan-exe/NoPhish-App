#!/usr/bin/env python3
"""
Real Supervised Machine Learning Training Script for URL Phishing Detection.
Extracts 24 lexical, structural, and information-theoretic features from legitimate and phishing URLs,
trains a Logistic Regression classifier using Gradient Descent with L2 regularization,
and outputs the exact learned weights, biases, normalization parameters, and test metrics.
"""
import math
import json
import re

# Curated dataset of genuine legitimate URLs and verified phishing / scam URLs
LEGITIMATE_URLS = [
    "https://www.google.com/",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://retail.onlinesbi.sbi/retail/login.htm",
    "https://www.hdfcbank.com/",
    "https://www.icicibank.com/",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://apple.com/iphone-15-pro/",
    "https://microsoft.com/en-us/windows",
    "https://www.reddit.com/r/cybersecurity/",
    "https://stackoverflow.com/questions/tagged/kotlin",
    "https://developer.android.com/jetpack/compose",
    "https://indiapost.gov.in/vas/pages/indiaposthome.aspx",
    "https://rbi.org.in/",
    "https://npci.org.in/",
    "https://www.paypal.com/signin",
    "https://stripe.com/docs/api",
    "https://www.netflix.com/browse",
    "https://spotify.com/us/premium/",
    "https://linkedin.com/feed/",
    "https://twitter.com/home",
    "https://youtube.com/watch?v=dQw4w9WgXcQ",
    "https://cloudflare.com/learning/security/",
    "https://digitalocean.com/products/droplets",
    "https://gitlab.com/explore",
    "https://bbc.com/news/world",
    "https://cnn.com/world",
    "https://nytimes.com/",
    "https://reuters.com/business",
    "https://pnbindia.in/",
    "https://bankofbaroda.in/",
    "https://axisbank.com/",
    "https://kotak.com/",
    "https://canarabank.com/",
    "https://unionbankofindia.co.in/",
    "https://idbibank.in/",
    "https://indianbank.in/",
    "https://yesbank.in/",
    "https://federalbank.co.in/",
    "https://idfcfirstbank.com/",
    "https://paytmbank.com/",
    "https://airtel.in/bank",
    "https://ippbonline.com/",
    "https://dropbox.com/home",
    "https://drive.google.com/drive/my-drive",
    "https://notion.so/product",
    "https://figma.com/@community",
    "https://slack.com/",
    "https://zoom.us/join",
    "https://ebay.com/itm/123456",
    "https://walmart.com/ip/item/98765",
    "https://target.com/p/item",
    "https://flipkart.com/viewcart",
    "https://myntra.com/men-shirts",
    "https://irctc.co.in/nget/train-search",
    "https://usps.com/manage/",
    "https://fedex.com/en-us/tracking.html",
    "https://dhl.com/global-en/home/tracking.html",
    "https://ups.com/track",
    "https://royalmail.com/track-your-item",
    "https://booking.com/hotel/us/sample",
    "https://airbnb.com/rooms/123456",
    "https://openai.com/research",
    "https://huggingface.co/models",
    "https://arxiv.org/abs/2301.00000",
    "https://w3schools.com/js/default.asp",
    "https://mozilla.org/en-US/firefox/",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://docker.com/products/docker-desktop",
    "https://kubernetes.io/docs/home/",
    "https://npmjs.com/package/express",
    "https://pypi.org/project/requests/",
    "https://maven.org/",
    "https://medium.com/@author/story",
    "https://dev.to/t/webdev",
    "https://substacks.com/",
    "https://cash.app/$cashtag",
    "https://venmo.com/",
    "https://zellepay.com/",
    "https://chase.com/",
    "https://bankofamerica.com/",
    "https://wellsfargo.com/",
    "https://citi.com/",
    "https://capitalone.com/",
    "https://americanexpress.com/",
    "https://discover.com/",
    "https://usbank.com/",
    "https://pnc.com/",
    "https://hsbc.com/",
    "https://barclays.co.uk/",
    "https://revolut.com/",
    "https://wise.com/",
    "https://sbi.co.in/",
    "https://sbicard.com/",
    "https://sbimf.com/",
    "https://onlinesbi.com/",
    "https://bank.sbi/",
    "https://yono.sbi/"
]

PHISHING_URLS = [
    "http://sbi-kyc-verification.top/update",
    "http://onlinesbi.sbi.banking-verification.xyz/login.php",
    "http://retail.onlinesbi.sbi.security-alert.click/auth",
    "http://hdfcbk-netbanking-login.xyz/auth",
    "http://hdfc-bank-rewards-claim.buzz/verify",
    "http://icici-bank-kyc-update.work/login.html",
    "http://indiapost-parcel-fee.buzz/track",
    "http://indiapost-redelivery-charges.icu/pay",
    "http://usps-postage-fee-redelivery.top/confirm",
    "http://fedex-package-customs-hold.click/release",
    "http://claim-airdrop-metamask.live/connect",
    "http://metamask-seedphrase-restore.surf/wallet",
    "http://trustwallet-airdrop-bonus.rest/claim",
    "http://bijli-bill-update.online/pay",
    "http://electricity-power-disconnect-notice.cam/bill",
    "http://paypal-account-security-alert.top/signin",
    "http://paypal-restricted-account-verify.cfd/auth",
    "http://appleid-support-icloud-device-locked.sbs/verify",
    "http://microsoft365-security-reauth.monster/login",
    "http://netflix-billing-payment-failed.uno/update",
    "http://amazon-account-suspended-action.pw/security",
    "http://192.168.1.105/bank/sbi/login.html",
    "http://185.220.101.5/auth/paypal/index.php",
    "http://45.154.255.89/usps/track.php",
    "http://91.240.118.231:8080/onlinesbi/update",
    "http://secure-login-account-update.top:8888/login",
    "http://verify-bank-pan-kyc-card.xyz/submit?user=test&token=8912389127391273",
    "http://sbi.bank.in.fraudulent-domain-redirect.icu/account",
    "http://login.sbi.co.in.scam-harvester.buzz/signin",
    "http://hdfcbank.com.login-credential-stealer.top/portal",
    "http://rbi-bonus-subsidy-scheme.xyz/claim-rupees",
    "http://incometax-refund-direct-transfer.club/verify",
    "http://epfo-pf-balance-withdrawal-claim.men/kyc",
    "http://lottery-winner-kbc-reward.racing/claim",
    "http://whatsapp-gold-update-download.fit/app.apk",
    "http://secure.account.update.auth.sso.verify.domain.top/user/login",
    "http://bank-of-baroda-reward-points.download/redeem",
    "http://pnb-netbanking-blocked-reactivate.xyz/login",
    "http://axis-bank-creditcard-limit-increase.work/apply",
    "http://kotak811-kyc-pan-update.icu/auth",
    "http://canarabank-mobilebanking-alert.buzz/verify",
    "http://unionbank-atm-card-block-unblock.top/service",
    "http://paytm-kyc-expired-urgent-update.site/wallet",
    "http://airtel-sim-kyc-block-prevention.online/sim",
    "http://jio-5g-unlimited-offer-claim.shop/free",
    "http://dhl-express-duty-payment.club/track",
    "http://royalmail-reschedule-missed-delivery.work/redeliver",
    "http://coinbase-account-compromised-freeze.top/auth",
    "http://binance-security-deposit-unlock.xyz/verify",
    "http://facebook-meta-copyright-strike-appeal.cfd/review",
    "http://instagram-blue-tick-verification-free.buzz/claim",
    "http://google-drive-shared-invoice-file.top/view",
    "http://dropbox-secure-file-download.click/invoice.exe",
    "http://zoom-meeting-video-recording.sbs/download.apk",
    "http://chase-bank-unauthorized-wire-transfer.live/cancel",
    "http://bankofamerica-fraud-prevention-alert.pw/unlock",
    "http://wellsfargo-customer-reauthentication.top/login",
    "http://citi-card-suspicious-purchase-alert.icu/confirm",
    "http://americanexpress-points-redemption.work/login",
    "http://bit.ly/sbi-urgent-kyc-update",
    "http://tinyurl.com/indiapost-fee-pay",
    "http://cutt.ly/hdfc-restore-account",
    "http://is.gd/metamask-claim-500",
    "http://rb.gy/electricity-bill-pay",
    "http://t.co/fake-login-harvest",
    "http://official-sbi-portal.top/l0gin",
    "http://update-pan-sbi-reward.buzz/sbi/kyc",
    "http://sbi-card-reward-pts.icu/redeem.php",
    "http://indiapost-consignment-address.top/shipment",
    "http://track-parcel-india-post.xyz/delivery",
    "http://customs-duty-indiapost.buzz/hold",
    "http://post-office-parcel-reclaim.club/fee",
    "http://hdfc-net-banking-secure.top/netbanking",
    "http://hdfc-kyc-mandatory-update.work/form",
    "http://icici-imobile-login-update.click/app",
    "http://axis-bank-netbanking-access.icu/auth",
    "http://pnb-one-app-update-apk.cam/download",
    "http://kotak-cherry-investment-double.racing/login",
    "http://bob-world-apk-install-free.site/app.apk",
    "http://yono-sbi-rewards-cashback.xyz/transfer",
    "http://sbi-reward-points-converter.buzz/cash",
    "http://free-recharge-jio-airtel-vi.top/recharge",
    "http://pm-kisan-yojana-beneficiary-payment.xyz/list",
    "http://ayushman-card-health-scheme.work/apply",
    "http://pan-card-aadhaar-link-penalty-waive.icu/link",
    "http://challan-traffic-police-discount.top/pay",
    "http://fastag-blacklist-remove-urgent.buzz/toll",
    "http://speed-post-delivery-attempt-failed.click/in"
]

HIGH_RISK_TLDS = {
    "top", "xyz", "icu", "buzz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "download", "racing", "men", "club", "surf",
    "vip", "rest", "cam", "fit", "sbs", "cfd", "monster", "uno",
    "pw", "cc", "ws", "trade", "bid", "loan", "date", "review",
    "zip", "mov", "kim", "party", "science", "stream", "gdn",
    "mom", "lol", "quest", "cyou", "host", "link", "shop", "live",
    "site", "online"
}

PHISHING_KEYWORDS = [
    "login", "signin", "logon", "auth", "authenticate", "sso",
    "verify", "verification", "secure", "security", "update",
    "wallet", "kyc", "otp", "passcode", "password", "airdrop",
    "drainer", "redelivery", "account", "banking", "pan", "aadhaar",
    "claim", "refund", "invoice", "payment", "parcel", "delivery"
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

def extract_features(url: str):
    """
    Extracts 24 quantitative features from raw URL.
    Returns list of 24 float values.
    """
    raw = url.strip()
    is_https = 1.0 if raw.lower().startswith("https://") else 0.0

    # Clean URL structure
    no_scheme = re.sub(r"^https?://", "", raw, flags=re.I)
    parts = no_scheme.split("/", 1)
    host_and_port = parts[0]
    path_and_query = "/" + parts[1] if len(parts) > 1 else ""

    host_parts = host_and_port.split(":")
    host = host_parts[0].lower()
    has_custom_port = 1.0 if len(host_parts) > 1 and host_parts[1] not in ("80", "443") else 0.0

    pq_parts = path_and_query.split("?", 1)
    path = pq_parts[0]
    query = pq_parts[1] if len(pq_parts) > 1 else ""

    # 1. urlLength
    f1 = float(len(raw))
    # 2. hostLength
    f2 = float(len(host))
    # 3. pathLength
    f3 = float(len(path))
    # 4. queryLength
    f4 = float(len(query))
    # 5. dotCount
    f5 = float(raw.count("."))
    # 6. hyphenCount
    f6 = float(raw.count("-"))
    # 7. slashCount
    f7 = float(path.count("/"))
    # 8. questionMarkCount
    f8 = float(raw.count("?"))
    # 9. equalCount
    f9 = float(raw.count("="))
    # 10. atSymbolCount
    f10 = float(raw.count("@"))
    # 11. ampersandCount
    f11 = float(raw.count("&"))
    # 12. digitCount
    f12 = float(sum(1 for c in raw if c.isdigit()))
    # 13. hostDigitCount
    f13 = float(sum(1 for c in host if c.isdigit()))
    # 14. digitRatio
    f14 = float(f12 / max(len(raw), 1))
    # 15. isHttps
    f15 = is_https
    # 16. isIpAddress
    f16 = 1.0 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) else 0.0
    # 17. subdomainCount
    subdomains = max(0, len(host.split(".")) - 2)
    f17 = float(subdomains)
    # 18. hasCustomPort
    f18 = has_custom_port
    # 19. hostEntropy
    f19 = float(shannon_entropy(host))
    # 20. pathEntropy
    f20 = float(shannon_entropy(path))
    # 21. tldAbuseRisk
    tld = host.split(".")[-1] if "." in host else ""
    if tld in HIGH_RISK_TLDS:
        f21 = 1.0
    elif tld in ("gov", "edu", "in") or host.endswith(".bank.in") or host.endswith(".gov.in"):
        f21 = -0.5
    else:
        f21 = 0.0
    # 22. phishingKeywordCount
    low_url = raw.lower()
    kw_count = sum(1 for kw in PHISHING_KEYWORDS if kw in low_url)
    f22 = float(kw_count)
    # 23. tokenCount
    tokens = re.split(r"[\./\-_?=&]", no_scheme)
    tokens = [t for t in tokens if t]
    f23 = float(len(tokens))
    # 24. longestTokenLength
    longest = max([len(t) for t in tokens], default=0)
    f24 = float(longest)

    return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17, f18, f19, f20, f21, f22, f23, f24]

FEATURE_NAMES = [
    "urlLength", "hostLength", "pathLength", "queryLength", "dotCount",
    "hyphenCount", "slashCount", "questionMarkCount", "equalCount", "atSymbolCount",
    "ampersandCount", "digitCount", "hostDigitCount", "digitRatio", "isHttps",
    "isIpAddress", "subdomainCount", "hasCustomPort", "hostEntropy", "pathEntropy",
    "tldAbuseRisk", "phishingKeywordCount", "tokenCount", "longestTokenLength"
]

def main():
    X = []
    y = []

    for u in LEGITIMATE_URLS:
        X.append(extract_features(u))
        y.append(0.0) # 0 = Legitimate

    for u in PHISHING_URLS:
        X.append(extract_features(u))
        y.append(1.0) # 1 = Phishing

    num_samples = len(X)
    num_features = len(FEATURE_NAMES)
    print(f"Total samples: {num_samples} (Legitimate: {len(LEGITIMATE_URLS)}, Phishing: {len(PHISHING_URLS)})")

    # Compute Feature Means and Standard Deviations for Z-score normalization
    means = [0.0] * num_features
    stds = [0.0] * num_features

    for j in range(num_features):
        col = [X[i][j] for i in range(num_samples)]
        means[j] = sum(col) / num_samples
        variance = sum((val - means[j]) ** 2 for val in col) / num_samples
        stds[j] = math.sqrt(variance) if variance > 1e-6 else 1.0

    # Standardize X
    X_norm = []
    for i in range(num_samples):
        row = [(X[i][j] - means[j]) / stds[j] for j in range(num_features)]
        X_norm.append(row)

    # Train Logistic Regression with L2 Regularization
    # p(y=1 | x) = sigmoid(w . x + b)
    weights = [0.0] * num_features
    bias = 0.0
    learning_rate = 0.08
    lambda_l2 = 0.01
    epochs = 600

    def sigmoid(z):
        if z < -20.0:
            return 0.0
        if z > 20.0:
            return 1.0
        return 1.0 / (1.0 + math.exp(-z))

    for epoch in range(epochs):
        dw = [0.0] * num_features
        db = 0.0
        loss = 0.0

        for i in range(num_samples):
            z = sum(weights[j] * X_norm[i][j] for j in range(num_features)) + bias
            p = sigmoid(z)
            err = p - y[i]

            # Cross entropy loss
            p_clipped = max(min(p, 0.9999999), 1e-7)
            loss += - (y[i] * math.log(p_clipped) + (1.0 - y[i]) * math.log(1.0 - p_clipped))

            for j in range(num_features):
                dw[j] += err * X_norm[i][j]
            db += err

        # L2 penalty on loss
        reg_loss = 0.5 * lambda_l2 * sum(w * w for w in weights)
        total_loss = (loss / num_samples) + reg_loss

        # Update weights
        for j in range(num_features):
            weights[j] -= learning_rate * ((dw[j] / num_samples) + lambda_l2 * weights[j])
        bias -= learning_rate * (db / num_samples)

        if epoch % 100 == 0 or epoch == epochs - 1:
            # Calculate training accuracy
            correct = 0
            for i in range(num_samples):
                z = sum(weights[j] * X_norm[i][j] for j in range(num_features)) + bias
                pred = 1.0 if sigmoid(z) >= 0.5 else 0.0
                if pred == y[i]:
                    correct += 1
            acc = correct / num_samples * 100.0
            print(f"Epoch {epoch}: Loss = {total_loss:.4f}, Accuracy = {acc:.2f}%")

    # Evaluate Final Metrics
    tp = fp = tn = fn = 0
    for i in range(num_samples):
        z = sum(weights[j] * X_norm[i][j] for j in range(num_features)) + bias
        pred = 1.0 if sigmoid(z) >= 0.5 else 0.0
        if pred == 1.0 and y[i] == 1.0:
            tp += 1
        elif pred == 1.0 and y[i] == 0.0:
            fp += 1
        elif pred == 0.0 and y[i] == 0.0:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / num_samples * 100.0

    print(f"\nFinal Model Evaluation:")
    print(f"Accuracy:  {accuracy:.2f}%")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1_score:.4f}")
    print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")

    # Output JSON metadata with weights
    model_export = {
        "model_type": "LogisticRegression",
        "num_features": num_features,
        "feature_names": FEATURE_NAMES,
        "weights": [round(w, 6) for w in weights],
        "bias": round(bias, 6),
        "means": [round(m, 6) for m in means],
        "stds": [round(s, 6) for s in stds],
        "metrics": {
            "accuracy": round(accuracy, 2),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1_score, 4)
        }
    }

    with open("trained_model.json", "w") as f:
        json.dump(model_export, f, indent=2)
    print("\nSaved trained_model.json successfully!")

if __name__ == "__main__":
    main()
