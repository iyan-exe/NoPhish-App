package com.example.domain

import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.roundToInt

data class FeatureContribution(
    val featureName: String,
    val rawValue: Float,
    val contribution: Float,
    val isRiskIndication: Boolean,
    val description: String
)

data class MlInferenceResult(
    val probability: Float,
    val isPhishing: Boolean,
    val confidencePercentage: Float,
    val riskScore: Int,
    val rawLogit: Float,
    val topContributors: List<FeatureContribution>,
    val features: ExtractedUrlFeatures
)

/**
 * Supervised Machine Learning Classifier for URL Phishing Detection.
 *
 * Executes real supervised inference via a trained regularized Logistic Regression model
 * on a 24-dimensional normalized feature space.
 * Weights and normalization parameters were trained on an empirical dataset of
 * verified legitimate domains (global top sites, verified banks, government portals)
 * and active phishing vectors.
 */
object SupervisedUrlClassifier {

    // Feature means from dataset standardization
    private val FEATURE_MEANS = floatArrayOf(
        36.55615f, 20.764706f, 7.957219f, 0.240642f, 1.347594f,
        1.368984f, 1.304813f, 0.010695f, 0.016043f, 0.010695f,
        0.005348f, 0.588235f, 0.262032f, 0.014845f, 0.529412f,
        0.02139f, 0.262032f, 0.010695f, 3.400114f, 2.171144f,
        0.382353f, 0.695187f, 4.770053f, 8.299465f
    )

    // Feature standard deviations from dataset standardization
    private val FEATURE_STDS = floatArrayOf(
        12.318014f, 11.761363f, 6.108492f, 2.514313f, 0.828653f,
        1.526136f, 0.601361f, 0.102863f, 0.162729f, 0.102863f,
        0.072931f, 2.262569f, 1.513152f, 0.054573f, 0.499134f,
        0.144682f, 0.73913f, 0.102863f, 0.573934f, 0.735166f,
        0.580796f, 1.018903f, 2.115858f, 3.655977f
    )

    // Supervised Model Learned Weights (L2 Regularized Logistic Regression)
    private val WEIGHTS = floatArrayOf(
        0.396033f,  // urlLength
        0.393742f,  // hostLength
        0.166926f,  // pathLength
        -0.035908f, // queryLength
        -0.098992f, // dotCount
        0.869102f,  // hyphenCount
        -0.667304f, // slashCount
        -0.079954f, // questionMarkCount
        -0.045160f, // equalCount
        -0.089820f, // atSymbolCount
        0.012003f,  // ampersandCount
        0.115411f,  // digitCount
        0.261134f,  // hostDigitCount
        0.099331f,  // digitRatio
        -1.403636f, // isHttps (strongly reduces risk when true)
        0.266876f,  // isIpAddress
        -0.072195f, // subdomainCount
        0.052187f,  // hasCustomPort
        0.077601f,  // hostEntropy
        0.272485f,  // pathEntropy
        0.711098f,  // tldAbuseRisk (.top, .xyz, etc.)
        0.528144f,  // phishingKeywordCount
        0.546619f,  // tokenCount
        0.069143f   // longestTokenLength
    )

    // Model Learned Bias
    private const val BIAS = -0.06157f

    private fun sigmoid(z: Float): Float {
        return when {
            z < -20.0f -> 0.0f
            z > 20.0f -> 1.0f
            else -> (1.0f / (1.0f + exp(-z)))
        }
    }

    private fun describeFeatureContribution(name: String, rawValue: Float, contribution: Float): String {
        return when (name) {
            "isHttps" -> if (rawValue > 0.5f) "Valid HTTPS encryption protocol (-$1.40 logit reduction)" else "Unencrypted plain HTTP scheme (Risk amplification)"
            "hyphenCount" -> "Hyphen stuffing (${rawValue.toInt()} hyphens in domain, +${"%.2f".format(contribution)} logit)"
            "tldAbuseRisk" -> if (rawValue > 0.5f) "High-abuse TLD flagged in registry (+${"%.2f".format(contribution)} logit)" else "Standard or institutional TLD"
            "phishingKeywordCount" -> "Security/lure keyword count: ${rawValue.toInt()} detected (+${"%.2f".format(contribution)} logit)"
            "tokenCount" -> "High subdomain / token segmentation (${rawValue.toInt()} tokens, +${"%.2f".format(contribution)} logit)"
            "isIpAddress" -> if (rawValue > 0.5f) "Raw IP host bypassing DNS naming (+${"%.2f".format(contribution)} logit)" else "Standard DNS hostname"
            "hostEntropy" -> "Host Shannon entropy: ${"%.2f".format(rawValue)} bits (DGA variance: +${"%.2f".format(contribution)})"
            "pathEntropy" -> "Path entropy: ${"%.2f".format(rawValue)} bits (+${"%.2f".format(contribution)})"
            "hostDigitCount" -> "Numerical digits in host: ${rawValue.toInt()} (+${"%.2f".format(contribution)})"
            "urlLength" -> "URL length: ${rawValue.toInt()} chars (+${"%.2f".format(contribution)})"
            else -> "$name: $rawValue (contribution: ${"%.2f".format(contribution)})"
        }
    }

    /**
     * Executes supervised inference on a URL.
     */
    fun predict(url: String): MlInferenceResult {
        val features = UrlFeatureExtractor.extract(url)
        return predictFeatures(features)
    }

    fun predictFeatures(features: ExtractedUrlFeatures): MlInferenceResult {
        val vector = features.vector
        var logit = BIAS
        val contributions = mutableListOf<FeatureContribution>()

        for (i in vector.indices) {
            val mean = FEATURE_MEANS[i]
            val std = if (FEATURE_STDS[i] > 1e-6f) FEATURE_STDS[i] else 1.0f
            val standardized = (vector[i] - mean) / std
            val contribution = WEIGHTS[i] * standardized
            logit += contribution

            contributions.add(
                FeatureContribution(
                    featureName = UrlFeatureExtractor.FEATURE_NAMES[i],
                    rawValue = vector[i],
                    contribution = contribution,
                    isRiskIndication = contribution > 0.1f,
                    description = describeFeatureContribution(
                        UrlFeatureExtractor.FEATURE_NAMES[i],
                        vector[i],
                        contribution
                    )
                )
            )
        }

        val probability = sigmoid(logit)
        val isPhishing = probability >= 0.5f
        val confidence = (abs(probability - 0.5f) * 2.0f * 100.0f).coerceIn(0.0f, 100.0f)
        val riskScore = (probability * 100.0f).roundToInt().coerceIn(0, 100)

        // Sort by absolute contribution impact
        val sortedContributions = contributions.sortedByDescending { abs(it.contribution) }

        return MlInferenceResult(
            probability = probability,
            isPhishing = isPhishing,
            confidencePercentage = confidence,
            riskScore = riskScore,
            rawLogit = logit,
            topContributors = sortedContributions.take(6),
            features = features
        )
    }
}
