package com.example.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.example.data.model.ScanHistoryEntity
import com.example.data.model.WhitelistEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanHistoryDao {
    @Query("SELECT * FROM scan_history ORDER BY scannedAt DESC")
    fun getAllScans(): Flow<List<ScanHistoryEntity>>

    @Query("SELECT * FROM scan_history WHERE id = :id LIMIT 1")
    suspend fun getScanById(id: Long): ScanHistoryEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(scan: ScanHistoryEntity): Long

    @Query("DELETE FROM scan_history WHERE id = :id")
    suspend fun deleteScanById(id: Long)

    @Query("DELETE FROM scan_history")
    suspend fun clearAll()

    @Query("SELECT COUNT(*) FROM scan_history")
    fun getScanCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM scan_history WHERE status = 'Phishing'")
    fun getPhishingCount(): Flow<Int>
}

@Dao
interface WhitelistDao {
    @Query("SELECT * FROM whitelist_domains ORDER BY brandName ASC")
    fun getAllWhitelisted(): Flow<List<WhitelistEntity>>

    @Query("SELECT * FROM whitelist_domains WHERE domain = :domain LIMIT 1")
    suspend fun findByDomain(domain: String): WhitelistEntity?

    @Query("SELECT COUNT(*) FROM whitelist_domains")
    suspend fun getCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: WhitelistEntity): Long

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(entities: List<WhitelistEntity>)

    @Query("DELETE FROM whitelist_domains WHERE id = :id")
    suspend fun deleteById(id: Long)
}

@Dao
interface ThreatIntelDao {
    @Query("SELECT * FROM threat_intel_repository ORDER BY addedAt DESC")
    fun getAllThreats(): Flow<List<com.example.data.model.ThreatIntelEntity>>

    @Query("SELECT * FROM threat_intel_repository WHERE title LIKE '%' || :query || '%' OR indicatorsOfCompromise LIKE '%' || :query || '%' OR targetBrand LIKE '%' || :query || '%' OR fakeDomain LIKE '%' || :query || '%'")
    fun searchThreats(query: String): Flow<List<com.example.data.model.ThreatIntelEntity>>

    @Query("SELECT * FROM threat_intel_repository WHERE category = :category ORDER BY addedAt DESC")
    fun getByCategory(category: String): Flow<List<com.example.data.model.ThreatIntelEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(threat: com.example.data.model.ThreatIntelEntity): Long

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(threats: List<com.example.data.model.ThreatIntelEntity>)

    @Query("DELETE FROM threat_intel_repository WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT COUNT(*) FROM threat_intel_repository")
    suspend fun getCount(): Int
}

