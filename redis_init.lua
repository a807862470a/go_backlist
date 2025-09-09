-- Redis初始化脚本
-- 用于设置Redis缓存结构和初始配置

-- =============================================
-- 系统配置缓存
-- =============================================

-- 设置系统配置
redis.call('SET', 'sys_config:detection_cost', '0.01')
redis.call('SET', 'sys_config:blacklist_cache_ttl', '3600')
redis.call('SET', 'sys_config:detection_cache_ttl', '86400')
redis.call('SET', 'sys_config:rate_limit_cache_ttl', '300')
redis.call('SET', 'sys_config:max_concurrent_requests', '100')
redis.call('SET', 'sys_config:request_timeout', '30')
redis.call('SET', 'sys_config:log_retention_days', '90')
redis.call('SET', 'sys_config:statistics_retention_days', '365')
redis.call('SET', 'sys_config:backup_retention_days', '30')
redis.call('SET', 'sys_config:maintenance_window_start', '02:00:00')
redis.call('SET', 'sys_config:maintenance_window_end', '04:00:00')

-- 设置配置TTL
redis.call('EXPIRE', 'sys_config:detection_cost', 86400)
redis.call('EXPIRE', 'sys_config:blacklist_cache_ttl', 86400)
redis.call('EXPIRE', 'sys_config:detection_cache_ttl', 86400)
redis.call('EXPIRE', 'sys_config:rate_limit_cache_ttl', 86400)
redis.call('EXPIRE', 'sys_config:max_concurrent_requests', 86400)
redis.call('EXPIRE', 'sys_config:request_timeout', 86400)
redis.call('EXPIRE', 'sys_config:log_retention_days', 86400)
redis.call('EXPIRE', 'sys_config:statistics_retention_days', 86400)
redis.call('EXPIRE', 'sys_config:backup_retention_days', 86400)
redis.call('EXPIRE', 'sys_config:maintenance_window_start', 86400)
redis.call('EXPIRE', 'sys_config:maintenance_window_end', 86400)

-- =============================================
-- 限流配置缓存
-- =============================================

-- 限流配置JSON数据
local rateLimitConfigs = {
    ['ip_daily_limit'] = {
        time_window = 86400,
        max_requests = 10000,
        block_duration = 3600,
        priority = 10
    },
    ['user_daily_limit'] = {
        time_window = 86400,
        max_requests = 50000,
        block_duration = 7200,
        priority = 20
    },
    ['api_daily_limit'] = {
        time_window = 86400,
        max_requests = 100000,
        block_duration = 7200,
        priority = 30
    },
    ['global_minute_limit'] = {
        time_window = 60,
        max_requests = 10000,
        block_duration = 300,
        priority = 5
    },
    ['login_limit'] = {
        time_window = 300,
        max_requests = 5,
        block_duration = 900,
        priority = 15
    },
    ['api_call_limit'] = {
        time_window = 60,
        max_requests = 100,
        block_duration = 60,
        priority = 25
    }
}

-- 设置限流配置
for configKey, configData in pairs(rateLimitConfigs) do
    redis.call('SET', 'rate_limit_config:' .. configKey, cjson.encode(configData))
    redis.call('EXPIRE', 'rate_limit_config:' .. configKey, 86400)
end

-- =============================================
-- 黑名单缓存初始化
-- =============================================

-- 创建黑名单集合
redis.call('SADD', 'blacklist_set:1', '13812345678', '13987654321')  -- 手机号
redis.call('SADD', 'blacklist_set:2', '01012345678')  -- 固话

-- 设置黑名单缓存
local blacklistData = {
    ['13812345678'] = {
        id = 1,
        number = '13812345678',
        number_type = 1,
        reason = '用户投诉骚扰电话',
        expire_at = '2024-12-31 23:59:59'
    },
    ['13987654321'] = {
        id = 2,
        number = '13987654321',
        number_type = 1,
        reason = '系统识别为空号',
        expire_at = nil
    },
    ['01012345678'] = {
        id = 3,
        number = '01012345678',
        number_type = 2,
        reason = '手动添加的固话',
        expire_at = '2024-12-31 23:59:59'
    }
}

-- 设置黑名单缓存
for number, data in pairs(blacklistData) do
    local cacheKey = 'blacklist:' .. number .. ':' .. data.number_type
    redis.call('SET', cacheKey, cjson.encode(data))
    
    -- 设置过期时间
    if data.expire_at then
        local expireTime = math.floor(tonumber(redis.call('TIME')[1]) + 30 * 24 * 3600)  -- 30天后过期
        redis.call('EXPIREAT', cacheKey, expireTime)
    else
        redis.call('EXPIRE', cacheKey, 86400 * 365)  -- 1年后过期
    end
end

-- =============================================
-- 空号检测结果缓存初始化
-- =============================================

-- 示例空号检测结果
local detectionResults = {
    ['13812345678'] = {
        result = 2,  -- 空号
        carrier = '中国移动',
        province = '北京',
        city = '北京',
        detection_time = '2024-01-01 12:00:00'
    },
    ['13987654321'] = {
        result = 3,  -- 停机
        carrier = '中国联通',
        province = '上海',
        city = '上海',
        detection_time = '2024-01-01 12:00:00'
    },
    ['15012345678'] = {
        result = 1,  -- 有效
        carrier = '中国电信',
        province = '广州',
        city = '广州',
        detection_time = '2024-01-01 12:00:00'
    }
}

-- 设置空号检测结果缓存
for number, data in pairs(detectionResults) do
    local cacheKey = 'number_detection:' .. number .. ':1'
    redis.call('SET', cacheKey, cjson.encode(data))
    redis.call('EXPIRE', cacheKey, 86400)  -- 1天后过期
end

-- =============================================
-- API密钥使用统计初始化
-- =============================================

-- 设置API密钥使用统计
redis.call('SET', 'api_key_usage:sk_test_1234567890abcdef:' .. os.date('%Y%m%d'), '0')
redis.call('EXPIRE', 'api_key_usage:sk_test_1234567890abcdef:' .. os.date('%Y%m%d'), 86400)

-- =============================================
-- 系统状态监控初始化
-- =============================================

-- 系统健康状态
redis.call('SET', 'system:health:status', 'healthy')
redis.call('SET', 'system:health:last_check', tostring(os.time()))
redis.call('SET', 'system:version', '1.0.0')
redis.call('SET', 'system:startup_time', tostring(os.time()))

-- 系统统计
redis.call('SET', 'system:stats:total_requests', '0')
redis.call('SET', 'system:stats:total_blacklist_checks', '0')
redis.call('SET', 'system:stats:total_detections', '0')
redis.call('SET', 'system:stats:total_rate_limits', '0')

-- =============================================
-- 队列初始化
-- =============================================

-- 创建任务队列
redis.call('LPUSH', 'queue:blacklist_sync', 'init_sync')
redis.call('LPUSH', 'queue:detection_tasks', 'init_detection')
redis.call('LPUSH', 'queue:statistics_update', 'init_stats')

-- 创建延迟队列
redis.call('ZADD', 'delayed_queue:cache_cleanup', os.time() + 3600, 'cleanup_expired_cache')
redis.call('ZADD', 'delayed_queue:database_cleanup', os.time() + 86400, 'cleanup_expired_data')

-- =============================================
-- 缓存预热数据
-- =============================================

-- 预热热门号码的检测结果
local hotNumbers = {
    '13800138000', '13900139000', '15000150000', '15800158000', '15900159000',
    '18600186000', '18700187000', '18800188000', '18900189000', '13000130000'
}

for i, number in ipairs(hotNumbers) do
    local cacheKey = 'number_detection:' .. number .. ':1'
    local mockData = {
        result = math.random(1, 4),
        carrier = '中国移动',
        province = '北京',
        city = '北京',
        detection_time = os.date('%Y-%m-%d %H:%M:%S')
    }
    redis.call('SET', cacheKey, cjson.encode(mockData))
    redis.call('EXPIRE', cacheKey, 3600)  -- 1小时后过期
end

-- =============================================
-- 布隆过滤器初始化
-- =============================================

-- 创建黑名单布隆过滤器
-- 注意：实际使用需要安装RedisBloom模块
-- redis.call('BF.ADD', 'bloom:blacklist', '13812345678')
-- redis.call('BF.ADD', 'bloom:blacklist', '13987654321')

-- 创建空号布隆过滤器
-- redis.call('BF.ADD', 'bloom:empty_numbers', '13812345678')
-- redis.call('BF.ADD', 'bloom:empty_numbers', '13987654321')

-- =============================================
-- 分布式锁初始化
-- =============================================

-- 创建分布式锁的key前缀
redis.call('SET', 'lock:blacklist_update:token', 'init_token')
redis.call('EXPIRE', 'lock:blacklist_update:token', 60)

redis.call('SET', 'lock:detection_task:token', 'init_token')
redis.call('EXPIRE', 'lock:detection_task:token', 60)

redis.call('SET', 'lock:statistics_update:token', 'init_token')
redis.call('EXPIRE', 'lock:statistics_update:token', 60)

-- =============================================
-- 会话管理初始化
-- =============================================

-- 创建会话清理任务
redis.call('SADD', 'session_cleanup_queue', 'init_cleanup')

-- =============================================
-- 性能监控初始化
-- =============================================

-- 创建性能监控key
redis.call('SET', 'monitor:response_time:avg', '0')
redis.call('SET', 'monitor:response_time:count', '0')
redis.call('SET', 'monitor:error_rate', '0')
redis.call('SET', 'monitor:concurrent_connections', '0')

-- 创建性能监控时间序列数据
for i = 0, 59 do
    local timestamp = os.time() - i * 60
    redis.call('HSET', 'monitor:metrics:response_time', tostring(timestamp), '0')
    redis.call('HSET', 'monitor:metrics:requests', tostring(timestamp), '0')
    redis.call('HSET', 'monitor:metrics:errors', tostring(timestamp), '0')
end

-- 设置监控数据过期时间
redis.call('EXPIRE', 'monitor:metrics:response_time', 3600)
redis.call('EXPIRE', 'monitor:metrics:requests', 3600)
redis.call('EXPIRE', 'monitor:metrics:errors', 3600)

-- =============================================
-- 限流计数器初始化
-- =============================================

-- 创建限流计数器清理任务
redis.call('SADD', 'rate_limit_cleanup_queue', 'init_cleanup')

-- =============================================
-- 完成初始化
-- =============================================

-- 设置初始化完成标记
redis.call('SET', 'system:initialized', 'true')
redis.call('SET', 'system:initialized_at', tostring(os.time()))
redis.call('SET', 'system:init_version', '1.0.0')

-- 返回初始化结果
local result = {
    status = 'success',
    message = 'Redis初始化完成',
    timestamp = os.time(),
    version = '1.0.0',
    initialized_keys = {
        'system_config',
        'rate_limit_config',
        'blacklist_cache',
        'detection_cache',
        'api_key_usage',
        'system_health',
        'system_stats',
        'task_queues',
        'distributed_locks',
        'performance_monitoring'
    }
}

return cjson.encode(result)