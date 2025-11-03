import { API_CONFIG, CACHE_KEYS } from '../utils/constants';

class CacheEntry {
  constructor(data, ttl = API_CONFIG.CACHE_CONFIG.DEFAULT_TTL) {
    this.data = data;
    this.timestamp = Date.now();
    this.ttl = ttl;
    this.accessCount = 0;
    this.lastAccess = this.timestamp;
  }

  isExpired() {
    return Date.now() - this.timestamp > this.ttl;
  }

  access() {
    this.accessCount++;
    this.lastAccess = Date.now();
    return this.data;
  }

  getAge() {
    return Date.now() - this.timestamp;
  }

  getRemainingTTL() {
    return Math.max(0, this.ttl - this.getAge());
  }
}

export class CacheManager {
  constructor() {
    this.cache = new Map();
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  // Generate cache key
  generateKey(prefix, identifier = '') {
    return `${prefix}:${identifier}`;
  }

  // Get item from cache
  get(key) {
    const entry = this.cache.get(key);
    
    if (!entry) {
      this.misses++;
      return null;
    }

    if (entry.isExpired()) {
      this.cache.delete(key);
      this.misses++;
      return null;
    }

    this.hits++;
    return entry.access();
  }

  // Set item in cache
  set(key, data, ttl = API_CONFIG.CACHE_CONFIG.DEFAULT_TTL) {
    // Check cache size limit
    if (this.cache.size >= API_CONFIG.CACHE_CONFIG.MAX_CACHE_SIZE) {
      this.evictLRU();
    }

    const entry = new CacheEntry(data, ttl);
    this.cache.set(key, entry);
    return true;
  }

  // Delete item from cache
  delete(key) {
    return this.cache.delete(key);
  }

  // Clear all cache entries
  clear() {
    this.cache.clear();
  }

  // Check if key exists and is not expired
  has(key) {
    const entry = this.cache.get(key);
    return entry && !entry.isExpired();
  }

  // Get cache statistics
  getStats() {
    const totalRequests = this.hits + this.misses;
    const hitRate = totalRequests > 0 ? (this.hits / totalRequests * 100).toFixed(2) : 0;
    
    return {
      size: this.cache.size,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      hitRate: `${hitRate}%`,
      maxSize: API_CONFIG.CACHE_CONFIG.MAX_CACHE_SIZE
    };
  }

  // Remove least recently used item
  evictLRU() {
    if (this.cache.size === 0) return;

    let oldestKey = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccess < oldestTime) {
        oldestTime = entry.lastAccess;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.evictions++;
    }
  }

  // Clean expired entries
  cleanExpired() {
    const expiredKeys = [];
    
    for (const [key, entry] of this.cache.entries()) {
      if (entry.isExpired()) {
        expiredKeys.push(key);
      }
    }

    expiredKeys.forEach(key => this.cache.delete(key));
    return expiredKeys.length;
  }

  // Get cache entry info
  getInfo(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;

    return {
      key,
      age: entry.getAge(),
      remainingTTL: entry.getRemainingTTL(),
      accessCount: entry.accessCount,
      lastAccess: entry.lastAccess,
      expired: entry.isExpired()
    };
  }

  // Predefined cache methods for common use cases
  cacheScanResults(scanId, results) {
    const key = this.generateKey(CACHE_KEYS.SCAN_RESULTS, scanId);
    return this.set(key, results, API_CONFIG.CACHE_CONFIG.SCAN_RESULTS_TTL);
  }

  getScanResults(scanId) {
    const key = this.generateKey(CACHE_KEYS.SCAN_RESULTS, scanId);
    return this.get(key);
  }

  cacheVulnerabilities(scanId, vulnerabilities) {
    const key = this.generateKey(CACHE_KEYS.VULNERABILITIES, scanId);
    return this.set(key, vulnerabilities, API_CONFIG.CACHE_CONFIG.VULNERABILITIES_TTL);
  }

  getVulnerabilities(scanId) {
    const key = this.generateKey(CACHE_KEYS.VULNERABILITIES, scanId);
    return this.get(key);
  }

  cacheHistory(page, limit, history) {
    const key = this.generateKey(CACHE_KEYS.HISTORY, `${page}_${limit}`);
    return this.set(key, history, API_CONFIG.CACHE_CONFIG.DEFAULT_TTL);
  }

  getHistory(page, limit) {
    const key = this.generateKey(CACHE_KEYS.HISTORY, `${page}_${limit}`);
    return this.get(key);
  }

  cacheStatistics(scanId, statistics) {
    const key = this.generateKey(CACHE_KEYS.STATISTICS, scanId);
    return this.set(key, statistics, API_CONFIG.CACHE_CONFIG.DEFAULT_TTL);
  }

  getStatistics(scanId) {
    const key = this.generateKey(CACHE_KEYS.STATISTICS, scanId);
    return this.get(key);
  }

  cacheHealthStatus(status) {
    const key = this.generateKey(CACHE_KEYS.HEALTH_STATUS);
    return this.set(key, status, 30000); // 30 seconds for health status
  }

  getHealthStatus() {
    const key = this.generateKey(CACHE_KEYS.HEALTH_STATUS);
    return this.get(key);
  }

  // Invalidate cache entries by pattern
  invalidatePattern(pattern) {
    const keysToDelete = [];
    
    for (const key of this.cache.keys()) {
      if (key.includes(pattern)) {
        keysToDelete.push(key);
      }
    }

    keysToDelete.forEach(key => this.cache.delete(key));
    return keysToDelete.length;
  }

  // Get all cache entries (for debugging)
  getAllEntries() {
    const entries = [];
    
    for (const [key] of this.cache.entries()) {
      entries.push({
        key,
        info: this.getInfo(key)
      });
    }
    
    return entries;
  }
}

// Create singleton instance
export const cacheManager = new CacheManager();

// Cache decorator for methods
export function cached(ttl = API_CONFIG.CACHE_CONFIG.DEFAULT_TTL, keyGenerator = null) {
  return function(target, propertyName, descriptor) {
    const method = descriptor.value;
    
    descriptor.value = async function(...args) {
      const cacheKey = keyGenerator 
        ? keyGenerator.apply(this, args) 
        : `${target.constructor.name}_${propertyName}_${JSON.stringify(args)}`;
      
      const cachedResult = cacheManager.get(cacheKey);
      if (cachedResult !== null) {
        return cachedResult;
      }

      const result = await method.apply(this, args);
      cacheManager.set(cacheKey, result, ttl);
      
      return result;
    };
    
    return descriptor;
  };
}

// Auto-cleanup expired entries periodically
setInterval(() => {
  const expiredCount = cacheManager.cleanExpired();
  if (expiredCount > 0 && process.env.NODE_ENV === 'development') {
    console.log(`Cache cleanup: removed ${expiredCount} expired entries`);
  }
}, 60000); // Clean every minute