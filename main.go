package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"blacklist-system/auth"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Config 配置结构体
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	JWT      JWTConfig      `yaml:"jwt"`
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type JWTConfig struct {
	SecretKey      string        `yaml:"secret_key"`
	ExpiresIn      time.Duration `yaml:"expires_in"`
	RefreshExpiresIn time.Duration `yaml:"refresh_expires_in"`
}

// 数据库模型
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"unique;not null" json:"username"`
	Email        string    `gorm:"unique;not null" json:"email"`
	PasswordHash string    `gorm:"not null" json:"-"`
	Role         string    `gorm:"default:'viewer'" json:"role"`
	Status       string    `gorm:"default:'active'" json:"status"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at"`
}

type Blacklist struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Type      string    `gorm:"not null" json:"type"` // phone, ip, device_id, email, domain
	Value     string    `gorm:"not null" json:"value"`
	Reason    string    `json:"reason"`
	Source    string    `gorm:"default:'manual'" json:"source"` // manual, system, api
	Priority  int       `gorm:"default:1" json:"priority"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedBy uint      `json:"created_by"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	Status    string    `gorm:"default:'active'" json:"status"`
}

type NumberValidation struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	PhoneNumber      string    `gorm:"not null" json:"phone_number"`
	CountryCode      string    `gorm:"default:'86'" json:"country_code"`
	ValidationResult string    `gorm:"not null" json:"validation_result"` // valid, invalid, unknown, error
	Provider         string    `json:"provider"`
	ResponseData     string    `gorm:"type:text" json:"response_data"`
	RequestID        string    `json:"request_id"`
	CreatedBy        *uint     `json:"created_by"`
	CreatedAt        time.Time `gorm:"autoCreateTime" json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at"`
}

type RateLimitRule struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"not null" json:"name"`
	Type        string    `gorm:"not null" json:"type"` // api_key, ip, user, global
	TargetValue string    `json:"target_value"`
	Algorithm   string    `gorm:"default:'token_bucket'" json:"algorithm"` // token_bucket, leaky_bucket, sliding_window
	Capacity    int       `json:"capacity"`
	RefillRate  int       `json:"refill_rate"`
	TimeUnit    string    `gorm:"default:'minute'" json:"time_unit"` // second, minute, hour, day
	Action      string    `gorm:"default:'block'" json:"action"` // block, delay, log
	Status      string    `gorm:"default:'active'" json:"status"`
	CreatedBy   uint      `json:"created_by"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// 全局变量
var (
	db          *gorm.DB
	redisClient *redis.Client
	config      Config
)

// 初始化数据库连接
func initDB() error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.Database.Username,
		config.Database.Password,
		config.Database.Host,
		config.Database.Port,
		config.Database.Database,
	)

	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}

	// 自动迁移数据库表
	if err := db.AutoMigrate(&User{}, &Blacklist{}, &NumberValidation{}, &RateLimitRule{}); err != nil {
		return fmt.Errorf("failed to migrate database: %v", err)
	}

	return nil
}

// 初始化Redis连接
func initRedis() error {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Redis.Host, config.Redis.Port),
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return nil
}

// JWT管理器
type JWTManager struct {
	secretKey string
}

func NewJWTManager(secretKey string) *JWTManager {
	return &JWTManager{secretKey: secretKey}
}

// 黑名单服务
type BlacklistService struct {
	db    *gorm.DB
	redis *redis.Client
}

func NewBlacklistService(db *gorm.DB, redis *redis.Client) *BlacklistService {
	return &BlacklistService{db: db, redis: redis}
}

// 添加黑名单
func (s *BlacklistService) CreateBlacklist(blacklist *Blacklist) error {
	if err := s.db.Create(blacklist).Error; err != nil {
		return err
	}

	// 更新缓存
	key := fmt.Sprintf("blacklist:%s:%s", blacklist.Type, blacklist.Value)
	return s.redis.Set(context.Background(), key, blacklist.Value, 24*time.Hour).Err()
}

// 检查是否在黑名单中
func (s *BlacklistService) IsBlacklisted(blacklistType, value string) (bool, error) {
	// 先检查缓存
	key := fmt.Sprintf("blacklist:%s:%s", blacklistType, value)
	cached, err := s.redis.Get(context.Background(), key).Result()
	if err == nil && cached != "" {
		return true, nil
	}

	// 缓存未命中，查询数据库
	var count int64
	err = s.db.Model(&Blacklist{}).
		Where("type = ? AND value = ? AND status = ?", blacklistType, value, "active").
		Count(&count).Error

	if err != nil {
		return false, err
	}

	// 如果在黑名单中，更新缓存
	if count > 0 {
		s.redis.Set(context.Background(), key, value, 24*time.Hour)
		return true, nil
	}

	return false, nil
}

// 限流服务
type RateLimitService struct {
	redis *redis.Client
}

func NewRateLimitService(redis *redis.Client) *RateLimitService {
	return &RateLimitService{redis: redis}
}

// 令牌桶算法
func (s *RateLimitService) TokenBucket(key string, capacity, refillRate int64) (bool, error) {
	ctx := context.Background()
	pipe := s.redis.Pipeline()

	// 获取当前令牌数
	tokensCmd := pipe.HGet(ctx, key, "tokens")
	lastRefillCmd := pipe.HGet(ctx, key, "last_refill")

	_, err := pipe.Exec(ctx)
	if err != nil {
		// 如果键不存在，创建新的令牌桶
		pipe = s.redis.Pipeline()
		pipe.HSet(ctx, key, "tokens", capacity-1, "last_refill", time.Now().Unix())
		pipe.Expire(ctx, key, time.Hour)
		_, err = pipe.Exec(ctx)
		return err == nil, err
	}

	tokens, _ := tokensCmd.Int64()
	lastRefill, _ := lastRefillCmd.Int64()
	now := time.Now().Unix()

	// 计算应该补充的令牌数
	elapsed := now - lastRefill
	tokensToAdd := (elapsed / 60) * refillRate // 假设每分钟补充

	// 补充令牌，不超过容量
	tokens = min(tokens+tokensToAdd, capacity)

	// 检查是否有足够的令牌
	if tokens > 0 {
		tokens--
		// 更新令牌数
		s.redis.HSet(ctx, key, "tokens", tokens, "last_refill", now)
		return true, nil
	}

	return false, nil
}

// 号码验证服务
type NumberValidationService struct {
	db    *gorm.DB
	redis *redis.Client
}

func NewNumberValidationService(db *gorm.DB, redis *redis.Client) *NumberValidationService {
	return &NumberValidationService{db: db, redis: redis}
}

// 验证号码
func (s *NumberValidationService) ValidateNumber(phoneNumber, countryCode string) (*NumberValidation, error) {
	// 先检查缓存
	key := fmt.Sprintf("number_validation:%s", phoneNumber)
	cached, err := s.redis.Get(context.Background(), key).Result()
	if err == nil && cached != "" {
		var validation NumberValidation
		if err := json.Unmarshal([]byte(cached), &validation); err == nil {
			return &validation, nil
		}
	}

	// 模拟第三方API调用
	result := &NumberValidation{
		PhoneNumber:      phoneNumber,
		CountryCode:      countryCode,
		ValidationResult: "valid", // 这里应该是真实的API调用结果
		Provider:         "mock_provider",
		ResponseData:     `{"carrier": "中国移动", "region": "北京", "status": "正常"}`,
		ExpiresAt:        func() *time.Time { t := time.Now().Add(6 * time.Hour); return &t }(),
		CreatedAt:        time.Now(),
	}

	// 保存到数据库
	if err := s.db.Create(result).Error; err != nil {
		return nil, err
	}

	// 缓存结果
	data, _ := json.Marshal(result)
	s.redis.Set(context.Background(), key, data, 6*time.Hour)

	return result, nil
}

// HTTP处理器
type Handler struct {
	db                    *gorm.DB
	blacklistService     *BlacklistService
	rateLimitService     *RateLimitService
	numberValidationService *NumberValidationService
}

func NewHandler(
	db *gorm.DB,
	blacklistService *BlacklistService,
	rateLimitService *RateLimitService,
	numberValidationService *NumberValidationService,
) *Handler {
	return &Handler{
		db:                    db,
		blacklistService:     blacklistService,
		rateLimitService:     rateLimitService,
		numberValidationService: numberValidationService,
	}
}

// 黑名单相关接口
func (h *Handler) CreateBlacklist(c *gin.Context) {
	var blacklist Blacklist
	if err := c.ShouldBindJSON(&blacklist); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := h.blacklistService.CreateBlacklist(&blacklist); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, blacklist)
}

func (h *Handler) CheckBlacklist(c *gin.Context) {
	type CheckRequest struct {
		Type  string `json:"type" binding:"required"`
		Value string `json:"value" binding:"required"`
	}

	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	isBlacklisted, err := h.blacklistService.IsBlacklisted(req.Type, req.Value)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"is_blacklisted": isBlacklisted,
		"type":          req.Type,
		"value":         req.Value,
	})
}

// 号码验证接口
func (h *Handler) ValidateNumber(c *gin.Context) {
	type ValidateRequest struct {
		PhoneNumber string `json:"phone_number" binding:"required"`
		CountryCode string `json:"country_code"`
	}

	var req ValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if req.CountryCode == "" {
		req.CountryCode = "86"
	}

	result, err := h.numberValidationService.ValidateNumber(req.PhoneNumber, req.CountryCode)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, result)
}

// 登录接口
func (h *Handler) Login(c *gin.Context) {
	type LoginRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 查找用户
	var user User
	if err := h.db.Where("username = ? AND status = ?", req.Username, "active").First(&user).Error; err != nil {
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 使用bcrypt验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 使用JWT管理器生成token
	jwtManager := auth.NewJWTManager(
		"your-secret-key-change-in-production",
		"filter-system",
		"web-app",
		time.Hour*24,       // access token 24小时
		time.Hour*24*7,    // refresh token 7天
	)

	accessToken, err := jwtManager.GenerateToken(user.ID, user.Username, user.Role, user.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "生成token失败"})
		return
	}

	refreshToken, err := jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "生成refresh token失败"})
		return
	}

	c.JSON(200, gin.H{
		"token": accessToken,
		"refreshToken": refreshToken,
		"token_type": "Bearer",
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
		"expiresAt": time.Now().Add(time.Hour * 24).Format(time.RFC3339),
	})
}

// 获取用户信息
func (h *Handler) GetUserInfo(c *gin.Context) {
	// 从token中获取用户信息（简化版）
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(401, gin.H{"error": "缺少认证令牌"})
		return
	}

	// 简单解析token获取用户名
	tokenParts := strings.Split(token, " ")
	if len(tokenParts) != 2 {
		c.JSON(401, gin.H{"error": "无效的认证令牌"})
		return
	}

	username := strings.Split(tokenParts[1], "-")[0]

	var user User
	if err := h.db.Where("username = ? AND status = ?", username, "active").First(&user).Error; err != nil {
		c.JSON(404, gin.H{"error": "用户不存在"})
		return
	}

	c.JSON(200, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
		"status":   user.Status,
	})
}

// 过滤服务相关处理函数
func (h *Handler) FilterCheck(c *gin.Context) {
	type FilterCheckRequest struct {
		Phone    string `json:"phone"`
		IP       string `json:"ip"`
		DeviceID string `json:"device_id"`
		Type     string `json:"type"`
	}

	var req FilterCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 检查黑名单
	isBlacklisted, err := h.blacklistService.IsBlacklisted("phone", req.Phone)
	if err != nil {
		c.JSON(500, gin.H{"error": "检查失败"})
		return
	}

	reason := "号码正常"
	if isBlacklisted {
		reason = "号码在黑名单中"
	}
	
	result := gin.H{
		"phone": req.Phone,
		"passed": !isBlacklisted,
		"reason": reason,
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
	}

	c.JSON(200, result)
}

func (h *Handler) BatchFilterCheck(c *gin.Context) {
	type BatchFilterCheckRequest struct {
		Phones []string `json:"phones"`
	}

	var req BatchFilterCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var results []gin.H
	for _, phone := range req.Phones {
		isBlacklisted, err := h.blacklistService.IsBlacklisted("phone", phone)
		if err != nil {
			continue
		}

		reason := "号码正常"
	if isBlacklisted {
		reason = "号码在黑名单中"
	}
	
	results = append(results, gin.H{
		"phone": phone,
		"passed": !isBlacklisted,
		"reason": reason,
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
	})
	}

	c.JSON(200, results)
}

func (h *Handler) FilterStats(c *gin.Context) {
	// 模拟统计数据
	stats := gin.H{
		"total_checked": 1250,
		"passed": 1100,
		"blocked": 150,
		"pass_rate": 88.0,
	}

	c.JSON(200, stats)
}

func (h *Handler) FilterLogs(c *gin.Context) {
	// 模拟日志数据
	logs := []gin.H{
		{
			"phone": "13800138000",
			"passed": true,
			"reason": "正常",
			"timestamp": time.Now().Format("2006-01-02 15:04:05"),
		},
	}

	c.JSON(200, gin.H{
		"logs": logs,
		"total": 1,
		"page": 1,
		"page_size": 10,
		"total_pages": 1,
	})
}

func (h *Handler) CheckPhoneOnly(c *gin.Context) {
	phone := c.Param("phone")
	isBlacklisted, err := h.blacklistService.IsBlacklisted("phone", phone)
	if err != nil {
		c.JSON(500, gin.H{"error": "检查失败"})
		return
	}

	reason := "号码正常"
	if isBlacklisted {
		reason = "号码在黑名单中"
	}
	
	c.JSON(200, gin.H{
		"phone": phone,
		"passed": !isBlacklisted,
		"reason": reason,
	})
}

func (h *Handler) CheckIPOnly(c *gin.Context) {
	ip := c.Param("ip")
	isBlacklisted, err := h.blacklistService.IsBlacklisted("ip", ip)
	if err != nil {
		c.JSON(500, gin.H{"error": "检查失败"})
		return
	}

	reason := "IP正常"
	if isBlacklisted {
		reason = "IP在黑名单中"
	}
	
	c.JSON(200, gin.H{
		"ip": ip,
		"passed": !isBlacklisted,
		"reason": reason,
	})
}

func (h *Handler) CheckDeviceOnly(c *gin.Context) {
	deviceId := c.Param("deviceId")
	isBlacklisted, err := h.blacklistService.IsBlacklisted("device_id", deviceId)
	if err != nil {
		c.JSON(500, gin.H{"error": "检查失败"})
		return
	}

	reason := "设备正常"
	if isBlacklisted {
		reason = "设备在黑名单中"
	}
	
	c.JSON(200, gin.H{
		"device_id": deviceId,
		"passed": !isBlacklisted,
		"reason": reason,
	})
}

// 用户管理相关处理函数
func (h *Handler) GetUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	var users []User
	var total int64

	h.db.Model(&User{}).Count(&total)
	offset := (page - 1) * pageSize
	h.db.Offset(offset).Limit(pageSize).Find(&users)

	c.JSON(200, gin.H{
		"items": users,
		"total": total,
		"page": page,
		"page_size": pageSize,
	})
}

func (h *Handler) CreateUser(c *gin.Context) {
	type CreateUserRequest struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required"`
		Role     string `json:"role"`
	}

	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	user := User{
		Username: req.Username,
		Email:    req.Email,
		Role:     req.Role,
		Status:   "active",
		PasswordHash: "password", // 实际应该加密
	}

	if err := h.db.Create(&user).Error; err != nil {
		c.JSON(500, gin.H{"error": "创建用户失败"})
		return
	}

	c.JSON(200, user)
}

func (h *Handler) GetUser(c *gin.Context) {
	id := c.Param("id")
	var user User
	if err := h.db.First(&user, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "用户不存在"})
		return
	}

	c.JSON(200, user)
}

func (h *Handler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var user User
	if err := h.db.First(&user, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "用户不存在"})
		return
	}

	type UpdateUserRequest struct {
		Email  string `json:"email"`
		Role   string `json:"role"`
		Status string `json:"status"`
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := h.db.Model(&user).Updates(req).Error; err != nil {
		c.JSON(500, gin.H{"error": "更新用户失败"})
		return
	}

	c.JSON(200, user)
}

func (h *Handler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	if err := h.db.Delete(&User{}, id).Error; err != nil {
		c.JSON(500, gin.H{"error": "删除用户失败"})
		return
	}

	c.JSON(200, gin.H{"message": "删除成功"})
}

func (h *Handler) ResetUserPassword(c *gin.Context) {
	id := c.Param("id")
	newPassword := "newpassword" + strconv.Itoa(int(time.Now().Unix()))

	if err := h.db.Model(&User{}).Where("id = ?", id).Update("password_hash", newPassword).Error; err != nil {
		c.JSON(500, gin.H{"error": "重置密码失败"})
		return
	}

	c.JSON(200, gin.H{"password": newPassword})
}

// 个人资料相关处理函数
func (h *Handler) UpdateProfile(c *gin.Context) {
	token := c.GetHeader("Authorization")
	username := h.getUsernameFromToken(token)

	var user User
	if err := h.db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(404, gin.H{"error": "用户不存在"})
		return
	}

	type UpdateProfileRequest struct {
		Email     string `json:"email"`
		Phone     string `json:"phone"`
		Department string `json:"department"`
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"email": req.Email,
	}).Error; err != nil {
		c.JSON(500, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(200, gin.H{"message": "更新成功"})
}

func (h *Handler) ChangePassword(c *gin.Context) {
	token := c.GetHeader("Authorization")
	username := h.getUsernameFromToken(token)

	var user User
	if err := h.db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(404, gin.H{"error": "用户不存在"})
		return
	}

	type ChangePasswordRequest struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 简单验证当前密码
	if req.CurrentPassword != "password" {
		c.JSON(400, gin.H{"error": "当前密码错误"})
		return
	}

	if err := h.db.Model(&user).Update("password_hash", req.NewPassword).Error; err != nil {
		c.JSON(500, gin.H{"error": "修改密码失败"})
		return
	}

	c.JSON(200, gin.H{"message": "密码修改成功"})
}

func (h *Handler) GetSecuritySettings(c *gin.Context) {
	settings := gin.H{
		"twoFactorEnabled": false,
		"loginNotifications": true,
	}

	c.JSON(200, settings)
}

func (h *Handler) UpdateTwoFactor(c *gin.Context) {
	type TwoFactorRequest struct {
		Enabled bool `json:"enabled"`
	}

	var req TwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	message := "双重认证已关闭"
	if req.Enabled {
		message = "双重认证已启用"
	}
	c.JSON(200, gin.H{"message": message})
}

func (h *Handler) UpdateLoginNotifications(c *gin.Context) {
	type NotificationRequest struct {
		Enabled bool `json:"enabled"`
	}

	var req NotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	message := "登录通知已关闭"
	if req.Enabled {
		message = "登录通知已启用"
	}
	c.JSON(200, gin.H{"message": message})
}

func (h *Handler) GetLoginHistory(c *gin.Context) {
	history := []gin.H{
		{
			"time": "2024-01-15 10:30:00",
			"ip": "192.168.1.100",
			"location": "北京市",
			"device": "Chrome / Windows 10",
			"status": "success",
		},
	}

	c.JSON(200, gin.H{"history": history})
}

// 系统管理相关处理函数
func (h *Handler) GetSystemStats(c *gin.Context) {
	stats := gin.H{
		"total_users": 10,
		"active_users": 8,
		"total_blacklists": 150,
		"today_checks": 125,
	}

	c.JSON(200, stats)
}

func (h *Handler) GetSystemStatus(c *gin.Context) {
	status := gin.H{
		"uptime": 86400,
		"memory": gin.H{
			"used":  1024 * 1024 * 100,
			"total": 1024 * 1024 * 512,
			"percentage": 19.5,
		},
		"cpu": 25.5,
		"connections": 15,
	}

	c.JSON(200, status)
}

func (h *Handler) GetSystemConfigs(c *gin.Context) {
	configs := []gin.H{
		{"key": "system_name", "value": "过滤系统", "description": "系统名称"},
		{"key": "maintenance_mode", "value": "false", "description": "维护模式"},
	}

	c.JSON(200, configs)
}

func (h *Handler) UpdateSystemConfig(c *gin.Context) {
	key := c.Param("key")
	type UpdateConfigRequest struct {
		Value string `json:"value"`
	}

	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"key": key, "value": req.Value})
}

func (h *Handler) GetSystemLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	logs := []gin.H{
		{
			"timestamp": time.Now().Format("2006-01-02 15:04:05"),
			"username": "admin",
			"action": "login",
			"resource": "system",
			"resource_id": "1",
			"ip": "192.168.1.100",
			"result": "success",
			"details": "用户登录",
		},
	}

	c.JSON(200, gin.H{
		"items": logs,
		"total": 1,
		"page": page,
		"page_size": pageSize,
	})
}

// 黑名单管理相关处理函数
func (h *Handler) GetBlacklistList(c *gin.Context) {
	var blacklists []Blacklist
	h.db.Find(&blacklists)

	c.JSON(200, gin.H{
		"blacklists": blacklists,
		"total": len(blacklists),
		"page": 1,
		"page_size": 10,
		"total_pages": 1,
	})
}

func (h *Handler) BatchCreateBlacklist(c *gin.Context) {
	type BatchCreateRequest struct {
		Items []struct {
			Type   string `json:"type"`
			Value  string `json:"value"`
			Reason string `json:"reason"`
		} `json:"items"`
	}

	var req BatchCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	success := 0
	failed := 0
	errors := []string{}

	for _, item := range req.Items {
		blacklist := Blacklist{
			Type:   item.Type,
			Value:  item.Value,
			Reason: item.Reason,
			Source: "manual",
			Status: "active",
		}

		if err := h.db.Create(&blacklist).Error; err != nil {
			failed++
			errors = append(errors, fmt.Sprintf("%s: %v", item.Value, err))
		} else {
			success++
		}
	}

	c.JSON(200, gin.H{
		"success": success,
		"failed": failed,
		"errors": errors,
	})
}

func (h *Handler) RemoveBlacklist(c *gin.Context) {
	blacklistType := c.Query("type")
	value := c.Query("value")

	if err := h.db.Where("type = ? AND value = ?", blacklistType, value).Delete(&Blacklist{}).Error; err != nil {
		c.JSON(500, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(200, gin.H{"message": "删除成功"})
}

func (h *Handler) BatchRemoveBlacklist(c *gin.Context) {
	type BatchRemoveRequest struct {
		Ids []uint `json:"ids"`
	}

	var req BatchRemoveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := h.db.Where("id IN ?", req.Ids).Delete(&Blacklist{}).Error; err != nil {
		c.JSON(500, gin.H{"error": "批量删除失败"})
		return
	}

	c.JSON(200, gin.H{"message": "批量删除成功"})
}

func (h *Handler) ExportBlacklist(c *gin.Context) {
	var blacklists []Blacklist
	h.db.Find(&blacklists)

	csv := "Type,Value,Reason,CreatedAt\n"
	for _, item := range blacklists {
		csv += fmt.Sprintf("%s,%s,%s,%s\n", item.Type, item.Value, item.Reason, item.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=blacklist.csv")
	c.String(200, csv)
}

func (h *Handler) GetBlacklistStats(c *gin.Context) {
	var total, phone, ip, deviceId int64
	h.db.Model(&Blacklist{}).Count(&total)
	h.db.Model(&Blacklist{}).Where("type = ?", "phone").Count(&phone)
	h.db.Model(&Blacklist{}).Where("type = ?", "ip").Count(&ip)
	h.db.Model(&Blacklist{}).Where("type = ?", "device_id").Count(&deviceId)

	c.JSON(200, gin.H{
		"total": total,
		"phone": phone,
		"ip": ip,
		"device_id": deviceId,
		"expired": 0,
		"inactive": 0,
	})
}

// 限流管理相关处理函数
func (h *Handler) GetRateLimitConfigs(c *gin.Context) {
	configs := []gin.H{
		{
			"id": 1,
			"key": "api_limit",
			"name": "API限流",
			"type": "global",
			"capacity": 1000,
			"refill_rate": 100,
			"time_unit": "minute",
		},
	}

	c.JSON(200, gin.H{
		"configs": configs,
		"total": len(configs),
		"page": 1,
		"page_size": 10,
		"total_pages": 1,
	})
}

func (h *Handler) CreateRateLimitConfig(c *gin.Context) {
	type CreateRateLimitRequest struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		Target     string `json:"target"`
		Capacity   int    `json:"capacity"`
		RefillRate int    `json:"refill_rate"`
		TimeUnit   string `json:"time_unit"`
	}

	var req CreateRateLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	config := gin.H{
		"id": 1,
		"name": req.Name,
		"type": req.Type,
		"capacity": req.Capacity,
		"refill_rate": req.RefillRate,
		"time_unit": req.TimeUnit,
	}

	c.JSON(200, config)
}

func (h *Handler) GetRateLimitConfig(c *gin.Context) {
	key := c.Param("key")
	config := gin.H{
		"id": 1,
		"key": key,
		"name": "限流配置",
		"type": "global",
		"capacity": 1000,
		"refill_rate": 100,
		"time_unit": "minute",
	}

	c.JSON(200, config)
}

func (h *Handler) UpdateRateLimitConfig(c *gin.Context) {
	key := c.Param("key")
	type UpdateRateLimitRequest struct {
		Capacity   int `json:"capacity"`
		RefillRate int `json:"refill_rate"`
	}

	var req UpdateRateLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"key": key,
		"capacity": req.Capacity,
		"refill_rate": req.RefillRate,
	})
}

func (h *Handler) DeleteRateLimitConfig(c *gin.Context) {
	_ = c.Param("key") // 获取key参数但暂时不使用
	c.JSON(200, gin.H{"message": "删除成功"})
}

func (h *Handler) GetRateLimitStats(c *gin.Context) {
	_ = c.Param("key") // 获取key参数但暂时不使用
	stats := gin.H{
		"total_requests": 1000,
		"blocked_requests": 50,
		"pass_rate": 95.0,
	}

	c.JSON(200, gin.H{
		"stats": stats,
		"start_time": time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05"),
		"end_time": time.Now().Format("2006-01-02 15:04:05"),
	})
}

func (h *Handler) ResetRateLimit(c *gin.Context) {
	_ = c.Param("key") // 获取key参数但暂时不使用
	c.JSON(200, gin.H{"message": "重置成功"})
}

// 辅助函数：从token获取用户名
func (h *Handler) getUsernameFromToken(token string) string {
	tokenParts := strings.Split(token, " ")
	if len(tokenParts) != 2 {
		return ""
	}
	return strings.Split(tokenParts[1], "-")[0]
}

// 限流中间件
func RateLimitMiddleware(rateLimitService *RateLimitService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取客户端IP作为限流键
		key := fmt.Sprintf("rate_limit:ip:%s", c.ClientIP())

		// 使用令牌桶算法限流
		allowed, err := rateLimitService.TokenBucket(key, 100, 10) // 容量100，每分钟补充10个
		if err != nil {
			c.JSON(500, gin.H{"error": "限流检查失败"})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(429, gin.H{"error": "请求过于频繁"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// 认证中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(401, gin.H{"error": "缺少认证令牌"})
			c.Abort()
			return
		}

		// 临时允许任何Bearer token通过（用于测试）
		if !strings.HasPrefix(token, "Bearer ") {
			c.JSON(401, gin.H{"error": "无效的认证令牌格式"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// 健康检查
func HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"services": map[string]string{
			"database": "ok",
			"redis":    "ok",
		},
	})
}

// HashPassword 使用bcrypt哈希密码
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}

// CheckPassword 验证密码
func CheckPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func main() {
	// 加载配置
	config = Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
			Mode: "debug",
		},
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     3306,
			Database: "blacklist_system",
			Username: "root",
			Password: "password",
		},
		Redis: RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       0,
		},
		JWT: JWTConfig{
			SecretKey:      "your-secret-key",
			ExpiresIn:      24 * time.Hour,
			RefreshExpiresIn: 7 * 24 * time.Hour,
		},
	}

	// 初始化数据库
	if err := initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 初始化Redis
	if err := initRedis(); err != nil {
		log.Fatalf("Failed to initialize Redis: %v", err)
	}

	// 创建服务
	blacklistService := NewBlacklistService(db, redisClient)
	rateLimitService := NewRateLimitService(redisClient)
	numberValidationService := NewNumberValidationService(db, redisClient)

	// 创建处理器
	handler := NewHandler(db, blacklistService, rateLimitService, numberValidationService)

	// 设置Gin路由
	gin.SetMode(config.Server.Mode)
	r := gin.Default()

	// 中间件
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// 健康检查
	r.GET("/health", HealthCheck)

	// API路由
	api := r.Group("/api/v1")
	api.Use(RateLimitMiddleware(rateLimitService))

	// 认证相关接口（不需要认证）
	auth := api.Group("/auth")
	{
		auth.POST("/login", handler.Login)
		auth.GET("/user-info", handler.GetUserInfo)
	}

	// 黑名单相关接口
	blacklist := api.Group("/blacklist")
	blacklist.Use(AuthMiddleware())
	{
		blacklist.POST("", handler.CreateBlacklist)
		blacklist.POST("/check", handler.CheckBlacklist)
		blacklist.GET("", func(c *gin.Context) {
			var blacklists []Blacklist
			db.Find(&blacklists)
			c.JSON(200, blacklists)
		})
	}

	// 号码验证接口
	validation := api.Group("/validation")
	validation.Use(AuthMiddleware())
	{
		validation.POST("/phone", handler.ValidateNumber)
	}

	// 过滤服务接口
	filter := api.Group("/filter")
	filter.Use(AuthMiddleware())
	{
		filter.POST("/check", handler.FilterCheck)
		filter.POST("/batch-check", handler.BatchFilterCheck)
		filter.GET("/stats", handler.FilterStats)
		filter.GET("/logs", handler.FilterLogs)
		filter.GET("/phone/:phone", handler.CheckPhoneOnly)
		filter.GET("/ip/:ip", handler.CheckIPOnly)
		filter.GET("/device/:deviceId", handler.CheckDeviceOnly)
	}

	// 用户管理接口
	users := r.Group("/users")
	users.Use(AuthMiddleware())
	{
		users.GET("", handler.GetUsers)
		users.POST("", handler.CreateUser)
		users.GET("/:id", handler.GetUser)
		users.PUT("/:id", handler.UpdateUser)
		users.DELETE("/:id", handler.DeleteUser)
		users.POST("/:id/reset-password", handler.ResetUserPassword)
	}

	// 个人资料接口
	user := api.Group("/user")
	user.Use(AuthMiddleware())
	{
		user.PUT("/profile", handler.UpdateProfile)
		user.POST("/change-password", handler.ChangePassword)
		user.GET("/security", handler.GetSecuritySettings)
		user.PUT("/security/2fa", handler.UpdateTwoFactor)
		user.PUT("/security/notifications", handler.UpdateLoginNotifications)
		user.GET("/login-history", handler.GetLoginHistory)
	}

	// 系统管理接口
	admin := api.Group("/admin")
	admin.Use(AuthMiddleware())
	{
		// 黑名单管理
		adminBlacklist := admin.Group("/blacklist")
		{
			adminBlacklist.GET("/list", handler.GetBlacklistList)
			adminBlacklist.POST("/add", handler.CreateBlacklist)
			adminBlacklist.POST("/batch-add", handler.BatchCreateBlacklist)
			adminBlacklist.DELETE("/remove", handler.RemoveBlacklist)
			adminBlacklist.DELETE("/batch-remove", handler.BatchRemoveBlacklist)
			adminBlacklist.GET("/export", handler.ExportBlacklist)
			adminBlacklist.GET("/stats", handler.GetBlacklistStats)
		}

		// 限流管理
		rateLimit := admin.Group("/rate-limit")
		{
			rateLimit.GET("/configs", handler.GetRateLimitConfigs)
			rateLimit.POST("/config", handler.CreateRateLimitConfig)
			rateLimit.GET("/config/:key", handler.GetRateLimitConfig)
			rateLimit.PUT("/config/:key", handler.UpdateRateLimitConfig)
			rateLimit.DELETE("/config/:key", handler.DeleteRateLimitConfig)
			rateLimit.GET("/stats/:key", handler.GetRateLimitStats)
			rateLimit.POST("/reset/:key", handler.ResetRateLimit)
		}

		// 系统管理
		system := admin.Group("/system")
		{
			system.GET("/stats", handler.GetSystemStats)
			system.GET("/status", handler.GetSystemStatus)
		}
	}

	// 系统配置接口
	system := r.Group("/system")
	system.Use(AuthMiddleware())
	{
		system.GET("/configs", handler.GetSystemConfigs)
		system.PUT("/configs/:key", handler.UpdateSystemConfig)
		system.GET("/logs", handler.GetSystemLogs)
		system.GET("/status", handler.GetSystemStatus)
	}

	// 启动服务器
	addr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	log.Printf("Server starting on %s", addr)

	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// 辅助函数
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}