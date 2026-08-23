package com.example.data.api

import androidx.annotation.Keep
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST
import retrofit2.http.Query
import java.util.concurrent.TimeUnit

@Keep
@JsonClass(generateAdapter = true)
data class GeminiGenerateRequest(
    @param:Json(name = "contents")
    val contents: List<GeminiContent>,
    @param:Json(name = "generationConfig")
    val generationConfig: GeminiGenerationConfig? = null,
    @param:Json(name = "systemInstruction")
    val systemInstruction: GeminiContent? = null
)

@Keep
@JsonClass(generateAdapter = true)
data class GeminiContent(
    @param:Json(name = "parts")
    val parts: List<GeminiPart>,
    @param:Json(name = "role")
    val role: String? = null
)

@Keep
@JsonClass(generateAdapter = true)
data class GeminiPart(
    @param:Json(name = "text")
    val text: String
)

@Keep
@JsonClass(generateAdapter = true)
data class GeminiGenerationConfig(
    @param:Json(name = "responseMimeType")
    val responseMimeType: String? = "application/json",
    @param:Json(name = "temperature")
    val temperature: Float? = 0.2f
)

@Keep
@JsonClass(generateAdapter = true)
data class GeminiGenerateResponse(
    @param:Json(name = "candidates")
    val candidates: List<GeminiCandidate>? = null
)

@Keep
@JsonClass(generateAdapter = true)
data class GeminiCandidate(
    @param:Json(name = "content")
    val content: GeminiContent? = null
)

interface GeminiApiService {
    @POST("v1beta/models/{model}:generateContent")
    suspend fun generateContentWithModel(
        @retrofit2.http.Path("model") model: String,
        @Query("key") apiKey: String,
        @Body request: GeminiGenerateRequest
    ): GeminiGenerateResponse

    @POST("v1beta/models/gemini-2.5-flash:generateContent")
    suspend fun generateContent(
        @Query("key") apiKey: String,
        @Body request: GeminiGenerateRequest
    ): GeminiGenerateResponse
}

object RetrofitClient {
    private const val GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/"

    private val loggingInterceptor = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.NONE
    }

    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(loggingInterceptor)
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    private val retrofit = Retrofit.Builder()
        .baseUrl(GEMINI_BASE_URL)
        .client(okHttpClient)
        .addConverterFactory(MoshiConverterFactory.create())
        .build()

    val geminiService: GeminiApiService by lazy {
        retrofit.create(GeminiApiService::class.java)
    }
}
