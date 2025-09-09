# 数据库性能优化建议

## 1. 查询性能优化

### 1.1 索引优化策略

#### 1.1.1 复合索引设计原则
```sql
-- 优秀复合索引示例
-- 1. 高选择性列在前
CREATE INDEX idx_detection_composite ON number_detection(number, number_type, detection_result);

-- 2. 覆盖索引优化
CREATE INDEX idx_user_stats ON statistics(user_id, stat_date, stat_type);

-- 3. 避免过度索引
-- 不推荐：每个列单独索引
CREATE INDEX idx_number ON number_detection(number);
CREATE INDEX idx_number_type ON number_detection(number_type);
CREATE INDEX idx_detection_result ON number_detection(detection_result);

-- 推荐：复合索引
CREATE INDEX idx_detection_optimal ON number_detection(number, number_type, detection_result);
```

#### 1.1.2 索引监控与维护
```sql
-- 查看索引使用情况
SELECT 
    table_name,
    index_name,
    cardinality,
    non_unique,
    seq_in_index,
    column_name
FROM information_schema.statistics 
WHERE table_schema = 'filter_system'
ORDER BY table_name, index_name, seq_in_index;

-- 分析未使用的索引
SELECT 
    object_schema,
    object_name,
    index_name
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE index_name IS NOT NULL
AND count_star = 0
AND object_schema = 'filter_system';

-- 重建碎片化索引
ALTER TABLE number_detection ENGINE=InnoDB;
ALTER TABLE blacklist ENGINE=InnoDB;
```

### 1.2 查询优化技巧

#### 1.2.1 慢查询优化
```sql
-- 优化前：全表扫描
SELECT * FROM number_detection 
WHERE detection_result = 1 
AND detection_time > '2024-01-01'
ORDER BY detection_time DESC;

-- 优化后：使用索引
SELECT id, number, detection_result, detection_time, carrier
FROM number_detection 
WHERE detection_result = 1 
AND detection_time > '2024-01-01'
ORDER BY detection_time DESC
LIMIT 1000;

-- 使用EXPLAIN分析查询
EXPLAIN SELECT * FROM number_detection WHERE number = '13812345678';
```

#### 1.2.2 分页查询优化
```sql
-- 传统分页（大数据量时性能差）
SELECT * FROM number_detection ORDER BY detection_time DESC LIMIT 10000, 20;

-- 优化分页（使用游标）
SELECT * FROM number_detection 
WHERE detection_time < '2024-01-01 12:00:00'
ORDER BY detection_time DESC 
LIMIT 20;

-- 使用覆盖索引优化分页
SELECT t1.* FROM number_detection t1
JOIN (SELECT id FROM number_detection ORDER BY detection_time DESC LIMIT 10000, 20) t2 ON t1.id = t2.id;
```

### 1.3 JOIN优化
```sql
-- 优化前：使用子查询
SELECT * FROM users u 
WHERE u.id IN (SELECT user_id FROM api_keys WHERE status = 1);

-- 优化后：使用JOIN
SELECT u.* FROM users u
JOIN api_keys ak ON u.id = ak.user_id 
WHERE ak.status = 1;

-- 使用适当的JOIN类型
SELECT u.username, COUNT(ak.id) as api_key_count
FROM users u
LEFT JOIN api_keys ak ON u.id = ak.user_id
GROUP BY u.id, u.username;
```

## 2. 缓存优化策略

### 2.1 多级缓存架构
```
应用层 → 本地缓存(Caffeine) → Redis缓存 → 数据库
```

### 2.2 缓存配置优化
```yaml
# 本地缓存配置
caffeine:
  maximum-size: 10000
  expire-after-write: 300s
  expire-after-access: 180s
  record-stats: true

# Redis缓存配置
redis:
  key-prefix: "filter:"
  default-ttl: 3600s
  cache-null-values: false
  use-key-prefix: true
```

### 2.3 缓存策略优化
```java
// 黑名单缓存策略
@Cacheable(value = "blacklist", key = "#number + '_' + #type")
public Blacklist getBlacklist(String number, Integer type) {
    return blacklistMapper.findByNumberAndType(number, type);
}

// 空号检测结果缓存
@Cacheable(value = "detection", key = "#number", unless = "#result == null")
public DetectionResult detectNumber(String number) {
    return detectionService.detect(number);
}

// 缓存击穿防护
public Blacklist getBlacklistWithLock(String number, Integer type) {
    String key = "blacklist:" + number + ":" + type;
    Blacklist result = redisTemplate.opsForValue().get(key);
    
    if (result == null) {
        String lockKey = "lock:blacklist:" + number + ":" + type;
        Boolean locked = redisTemplate.opsForValue().setIfAbsent(lockKey, "1", 10, TimeUnit.SECONDS);
        
        if (locked) {
            try {
                result = blacklistMapper.findByNumberAndType(number, type);
                if (result != null) {
                    redisTemplate.opsForValue().set(key, result, 3600, TimeUnit.SECONDS);
                }
            } finally {
                redisTemplate.delete(lockKey);
            }
        }
    }
    
    return result;
}
```

## 3. 数据库配置优化

### 3.1 MySQL配置优化
```ini
# my.cnf 配置优化
[mysqld]
# 基础配置
port = 3306
socket = /var/run/mysqld/mysqld.sock
pid-file = /var/run/mysqld/mysqld.pid

# 字符集配置
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# 内存配置
innodb_buffer_pool_size = 4G  # 根据服务器内存调整
innodb_log_file_size = 256M
innodb_log_buffer_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT

# 连接配置
max_connections = 500
max_connect_errors = 100000
thread_cache_size = 50
thread_stack = 256K

# 查询缓存（MySQL 8.0+已移除）
# query_cache_type = 0
# query_cache_size = 0

# 慢查询配置
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 1
log_queries_not_using_indexes = 1

# InnoDB配置
innodb_file_per_table = 1
innodb_file_format = Barracuda
innodb_large_prefix = 1
innodb_read_io_threads = 8
innodb_write_io_threads = 8
innodb_thread_concurrency = 0

# 复制配置
server-id = 1
log-bin = mysql-bin
binlog_format = ROW
binlog_row_image = MINIMAL
expire_logs_days = 7
sync_binlog = 0
```

### 3.2 Redis配置优化
```ini
# redis.conf 配置优化
# 基础配置
port 6379
bind 0.0.0.0
timeout 300
tcp-keepalive 60

# 内存配置
maxmemory 2gb
maxmemory-policy allkeys-lru

# 持久化配置
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes

# AOF配置
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# 网络配置
tcp-backlog 511
# 禁用危险命令
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command KEYS ""
```

## 4. 连接池优化

### 4.1 HikariCP配置优化
```yaml
spring:
  datasource:
    hikari:
      # 连接池大小配置
      maximum-pool-size: 20
      minimum-idle: 5
      
      # 连接生命周期配置
      idle-timeout: 300000        # 5分钟
      max-lifetime: 1800000       # 30分钟
      connection-timeout: 30000   # 30秒
      
      # 连接检测配置
      connection-test-query: SELECT 1
      validation-timeout: 5000
      leak-detection-threshold: 60000
      
      # 性能优化
      allow-pool-suspension: false
      read-only: false
      register-mbeans: true
```

### 4.2 连接池监控
```java
// 连接池监控配置
@Bean
public HikariDataSource dataSource() {
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/filter_system");
    config.setUsername("filter_app");
    config.setPassword("Filter@2024#");
    
    // 性能配置
    config.setMaximumPoolSize(20);
    config.setMinimumIdle(5);
    config.setIdleTimeout(300000);
    config.setMaxLifetime(1800000);
    config.setConnectionTimeout(30000);
    
    // 监控配置
    config.setMetricRegistry(metricRegistry);
    config.setHealthCheckRegistry(healthCheckRegistry);
    
    return new HikariDataSource(config);
}
```

## 5. 分库分表优化

### 5.1 水平分表策略
```java
// 按时间分表算法
public class MonthShardingAlgorithm implements PreciseShardingAlgorithm<Timestamp> {
    @Override
    public String doSharding(Collection<String> tableNames, PreciseShardingValue<Timestamp> shardingValue) {
        Timestamp time = shardingValue.getValue();
        String month = new SimpleDateFormat("yyyyMM").format(time);
        for (String tableName : tableNames) {
            if (tableName.endsWith(month)) {
                return tableName;
            }
        }
        throw new IllegalArgumentException("No target table found for time: " + time);
    }
}

// 按用户ID分库算法
public class UserDatabaseShardingAlgorithm implements PreciseShardingAlgorithm<Long> {
    @Override
    public String doSharding(Collection<String> databaseNames, PreciseShardingValue<Long> shardingValue) {
        Long userId = shardingValue.getValue();
        int index = (int) (userId % databaseNames.size());
        return "ds_" + index;
    }
}
```

### 5.2 分库分表配置
```yaml
sharding:
  tables:
    number_detection:
      actual-data-nodes: ds_${0..3}.number_detection_${2024..2025}${(0..1).padLeft(2,'0')}
      table-strategy:
        standard:
          sharding-column: detection_time
          precise-algorithm-class-name: com.example.algorithm.MonthShardingAlgorithm
          range-algorithm-class-name: com.example.algorithm.MonthRangeShardingAlgorithm
      key-generator:
        column: id
        type: SNOWFLAKE
        props:
          worker-id: ${WORKER_ID:0}
```

## 6. 读写分离优化

### 6.1 读写分离配置
```yaml
spring:
  shardingsphere:
    rules:
      readwrite-splitting:
        data-sources:
          pr_ds:
            static-strategy:
              write-data-source-name: write_ds
              read-data-source-names:
                - read_ds_0
                - read_ds_1
            load-balancer-name: round_robin
        load-balancers:
          round_robin:
            type: ROUND_ROBIN
          weight:
            type: WEIGHT
            props:
              read_ds_0: 1
              read_ds_1: 2
```

### 6.2 主从同步监控
```java
// 主从延迟监控
@Component
public class ReplicationMonitor {
    
    @Scheduled(fixedRate = 30000)
    public void checkReplicationDelay() {
        try {
            Map<String, Object> status = jdbcTemplate.queryForMap("SHOW SLAVE STATUS");
            long delay = ((Number) status.get("Seconds_Behind_Master")).longValue();
            
            if (delay > 30) {
                log.warn("主从复制延迟过大: {} 秒", delay);
                // 发送告警
            }
        } catch (Exception e) {
            log.error("检查主从复制状态失败", e);
        }
    }
}
```

## 7. 性能监控与调优

### 7.1 性能指标监控
```java
// 性能指标收集
@Component
public class PerformanceMetrics {
    
    private final MeterRegistry meterRegistry;
    
    public void recordQueryTime(String operation, long duration) {
        Timer.Sample.start(meterRegistry)
            .stop(Timer.builder("database.query.time")
                .description("数据库查询时间")
                .tag("operation", operation)
                .register(meterRegistry));
    }
    
    public void recordCacheHit(String cacheName) {
        meterRegistry.counter("cache.hits", "cache", cacheName).increment();
    }
    
    public void recordCacheMiss(String cacheName) {
        meterRegistry.counter("cache.misses", "cache", cacheName).increment();
    }
}
```

### 7.2 慢查询分析
```java
// 慢查询拦截器
@Aspect
@Component
public class SlowQueryInterceptor {
    
    private static final long SLOW_QUERY_THRESHOLD = 1000; // 1秒
    
    @Around("execution(* com.example.mapper.*.*(..))")
    public Object intercept(ProceedingJoinPoint joinPoint) throws Throwable {
        long startTime = System.currentTimeMillis();
        
        try {
            Object result = joinPoint.proceed();
            long duration = System.currentTimeMillis() - startTime;
            
            if (duration > SLOW_QUERY_THRESHOLD) {
                log.warn("慢查询检测: {}.{} 耗时: {}ms", 
                    joinPoint.getSignature().getDeclaringTypeName(),
                    joinPoint.getSignature().getName(),
                    duration);
            }
            
            return result;
        } catch (Exception e) {
            log.error("查询执行失败", e);
            throw e;
        }
    }
}
```

## 8. 容量规划与扩展

### 8.1 容量规划指标
```sql
-- 容量规划查询
SELECT 
    '用户数' as metric,
    COUNT(*) as current_value,
    COUNT(*) * 1.2 as projected_value_6m,
    COUNT(*) * 1.5 as projected_value_1y
FROM users WHERE status = 1

UNION ALL

SELECT 
    '黑名单数' as metric,
    COUNT(*) as current_value,
    COUNT(*) * 1.5 as projected_value_6m,
    COUNT(*) * 2.0 as projected_value_1y
FROM blacklist WHERE status = 1

UNION ALL

SELECT 
    '日均检测量' as metric,
    COUNT(*) as current_value,
    COUNT(*) * 1.8 as projected_value_6m,
    COUNT(*) * 3.0 as projected_value_1y
FROM number_detection 
WHERE detection_time > DATE_SUB(NOW(), INTERVAL 1 DAY);
```

### 8.2 扩展策略
```yaml
# 水平扩展配置
scaling:
  # 自动扩展配置
  auto-scaling:
    enabled: true
    cpu-threshold: 70
    memory-threshold: 80
    connection-threshold: 80
    
  # 扩展策略
  strategy:
    read-replicas:
      min: 2
      max: 10
      scale-up-threshold: 70
      scale-down-threshold: 30
    
    database-shards:
      initial: 4
      max: 16
      shard-size-threshold: 1000000  # 每个分片最大记录数
```

## 9. 性能测试与优化

### 9.1 性能测试脚本
```bash
#!/bin/bash
# 性能测试脚本

# 并发测试
ab -n 10000 -c 100 -H "Authorization: Bearer test_token" \
   -p test_data.json -T application/json \
   http://localhost:8080/api/v1/detection/check

# 黑名单查询性能测试
for i in {1..1000}; do
    curl -X POST http://localhost:8080/api/v1/blacklist/check \
         -H "Content-Type: application/json" \
         -d '{"number": "13812345678", "type": 1}' &
done

wait
```

### 9.2 性能基准
```yaml
# 性能基准配置
benchmarks:
  # 查询性能基准
  query:
    blacklist-check:
      target-p95: 50ms
      target-p99: 100ms
      max-concurrent: 1000
    
    number-detection:
      target-p95: 200ms
      target-p99: 500ms
      max-concurrent: 500
  
  # 缓存性能基准
  cache:
    hit-rate:
      target: 95%
      warning: 90%
      critical: 80%
    
    response-time:
      target-p95: 10ms
      target-p99: 20ms
  
  # 系统性能基准
  system:
    throughput:
      target: 10000 req/s
      max-concurrent: 5000
    
    availability:
      target: 99.9%
      max-downtime: 43min/month
```

## 10. 优化检查清单

### 10.1 日常优化检查
- [ ] 检查慢查询日志
- [ ] 分析索引使用情况
- [ ] 监控缓存命中率
- [ ] 检查连接池状态
- [ ] 验证主从同步状态

### 10.2 周期性优化任务
- [ ] 每周：重建碎片化索引
- [ ] 每月：优化表结构
- [ ] 每季度：容量规划评估
- [ ] 每半年：性能基准测试

### 10.3 性能优化最佳实践
1. **避免过度索引**：每个表索引数量不超过5个
2. **合理使用缓存**：热点数据缓存，冷数据不缓存
3. **监控关键指标**：QPS、响应时间、错误率、缓存命中率
4. **定期维护**：优化表、重建索引、清理过期数据
5. **容量规划**：提前规划扩展策略，避免性能瓶颈

这个性能优化文档提供了全面的数据库性能优化方案，包括查询优化、缓存策略、连接池配置、分库分表、读写分离等关键优化点。