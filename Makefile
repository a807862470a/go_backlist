# Blacklist System Makefile

.PHONY: help build run test clean docker-build docker-up docker-down deps vet fmt lint

# 默认目标
help:
	@echo "Available commands:"
	@echo "  build         - Build the application"
	@echo "  run           - Run the application"
	@echo "  test          - Run tests"
	@echo "  clean         - Clean build artifacts"
	@echo "  docker-build  - Build Docker images"
	@echo "  docker-up     - Start Docker containers"
	@echo "  docker-down   - Stop Docker containers"
	@echo "  deps          - Download dependencies"
	@echo "  vet           - Run go vet"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Run linter"
	@echo "  migrate       - Run database migrations"
	@echo "  seed          - Seed database with test data"
	@echo "  swagger       - Generate Swagger documentation"
	@echo "  coverage      - Generate test coverage report"
	@echo "  bench         - Run benchmarks"
	@echo "  install       - Install the application"

# 变量定义
APP_NAME := blacklist-system
VERSION := 1.0.0
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD)
BUILD_FLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# 构建应用
build:
	@echo "Building $(APP_NAME)..."
	go build $(BUILD_FLAGS) -o bin/$(APP_NAME) ./cmd/main.go

# 运行应用
run: build
	@echo "Running $(APP_NAME)..."
	./bin/$(APP_NAME)

# 运行测试
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

# 清理构建文件
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf coverage.out
	rm -rf coverage.html
	go clean ./...

# 下载依赖
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# 运行go vet
vet:
	@echo "Running go vet..."
	go vet ./...

# 格式化代码
fmt:
	@echo "Formatting Go code..."
	go fmt ./...

# 运行linter
lint:
	@echo "Running linter..."
	golangci-lint run

# 构建Docker镜像
docker-build:
	@echo "Building Docker images..."
	docker build -t $(APP_NAME):$(VERSION) -f Dockerfile .
	docker build -t $(APP_NAME)-gateway:$(VERSION) -f Dockerfile.gateway .
	docker build -t $(APP_NAME)-auth:$(VERSION) -f Dockerfile.auth .
	docker build -t $(APP_NAME)-blacklist:$(VERSION) -f Dockerfile.blacklist .
	docker build -t $(APP_NAME)-validation:$(VERSION) -f Dockerfile.validation .
	docker build -t $(APP_NAME)-ratelimit:$(VERSION) -f Dockerfile.ratelimit .

# 启动Docker容器
docker-up:
	@echo "Starting Docker containers..."
	docker-compose up -d

# 停止Docker容器
docker-down:
	@echo "Stopping Docker containers..."
	docker-compose down

# 重启Docker容器
docker-restart: docker-down docker-up

# 查看Docker容器状态
docker-logs:
	docker-compose logs -f

# 运行数据库迁移
migrate:
	@echo "Running database migrations..."
	mysql -h localhost -u root -p blacklist_system < scripts/init.sql

# 填充测试数据
seed:
	@echo "Seeding database with test data..."
	go run ./scripts/seed.go

# 生成Swagger文档
swagger:
	@echo "Generating Swagger documentation..."
	swag init -g ./cmd/main.go -o ./docs

# 生成测试覆盖率报告
coverage: test
	@echo "Generating test coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# 运行基准测试
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# 安装应用
install: build
	@echo "Installing $(APP_NAME)..."
	sudo cp bin/$(APP_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(APP_NAME)

# 创建必要的目录
setup:
	@echo "Creating necessary directories..."
	mkdir -p bin/
	mkdir -p logs/
	mkdir -p uploads/
	mkdir -p temp/
	mkdir -p backups/
	mkdir -p config/

# 开发环境设置
dev-setup: setup deps
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install github.com/air-verse/air@latest

# 热重载开发
dev:
	@echo "Starting development server with hot reload..."
	air -c .air.toml

# 生产环境构建
build-prod:
	@echo "Building for production..."
	CGO_ENABLED=0 GOOS=linux go build $(BUILD_FLAGS) -o bin/$(APP_NAME)-linux ./cmd/main.go
	CGO_ENABLED=0 GOOS=darwin go build $(BUILD_FLAGS) -o bin/$(APP_NAME)-darwin ./cmd/main.go
	CGO_ENABLED=0 GOOS=windows go build $(BUILD_FLAGS) -o bin/$(APP_NAME)-windows.exe ./cmd/main.go

# 创建发布包
package: build-prod
	@echo "Creating release package..."
	mkdir -p release/
	cp -r config/ release/
	cp -r scripts/ release/
	cp bin/$(APP_NAME)-linux release/
	cp bin/$(APP_NAME)-darwin release/
	cp bin/$(APP_NAME)-windows.exe release/
	cp README.md release/
	cp docker-compose.yml release/
	tar -czf release/$(APP_NAME)-$(VERSION).tar.gz release/

# 清理发布文件
clean-release:
	@echo "Cleaning release files..."
	rm -rf release/

# 健康检查
health:
	@echo "Checking service health..."
	curl -f http://localhost:8080/health || exit 1

# 运行所有检查
check: vet fmt lint test
	@echo "All checks passed!"

# 开发模式运行
run-dev:
	@echo "Running in development mode..."
	go run ./cmd/main.go

# 监控应用
monitor:
	@echo "Starting monitoring..."
	docker-compose up -d prometheus grafana

# 查看监控仪表板
dashboard:
	@echo "Opening monitoring dashboard..."
	open http://localhost:3000

# 数据库备份
backup-db:
	@echo "Backing up database..."
	mysqldump -h localhost -u root -p blacklist_system > backups/database_$(shell date +%Y%m%d_%H%M%S).sql

# 恢复数据库
restore-db:
	@echo "Restoring database from backup..."
	mysql -h localhost -u root -p blacklist_system < $(BACKUP_FILE)

# 日志轮转
rotate-logs:
	@echo "Rotating logs..."
	mv logs/app.log logs/app.log.$(shell date +%Y%m%d_%H%M%S)
	touch logs/app.log

# 性能分析
profile:
	@echo "Starting performance profiling..."
	go run ./cmd/main.go -cpuprofile=cpu.prof -memprofile=mem.prof

# 生成依赖图
deps-graph:
	@echo "Generating dependency graph..."
	go mod graph | dot -T png -o deps.png

# 安全扫描
security-scan:
	@echo "Running security scan..."
	gosec ./...

# 代码质量检查
quality-check: vet fmt lint security-scan test
	@echo "Code quality check completed!"

# 部署到测试环境
deploy-test:
	@echo "Deploying to test environment..."
	docker-compose -f docker-compose.yml -f docker-compose.test.yml up -d

# 部署到生产环境
deploy-prod:
	@echo "Deploying to production environment..."
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 回滚部署
rollback:
	@echo "Rolling back deployment..."
	docker-compose rollback

# 更新依赖
update-deps:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# 检查依赖漏洞
audit-deps:
	@echo "Auditing dependencies for vulnerabilities..."
	go audit ./...

# 创建数据库用户
create-db-user:
	@echo "Creating database user..."
	mysql -h localhost -u root -p -e "CREATE USER IF NOT EXISTS 'blacklist_user'@'localhost' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON blacklist_system.* TO 'blacklist_user'@'localhost'; FLUSH PRIVILEGES;"

# 初始化项目
init: setup deps create-db-user migrate
	@echo "Project initialized successfully!"
	@echo "Run 'make run-dev' to start the development server."

# 完整的CI/CD流程
ci: quality-check build-prod package
	@echo "CI/CD pipeline completed successfully!"

# 帮助信息
help-full:
	@echo "Blacklist System Development Commands"
	@echo "====================================="
	@echo ""
	@echo "Development:"
	@echo "  make dev-setup   - Setup development environment"
	@echo "  make dev         - Start development server with hot reload"
	@echo "  make run-dev     - Run in development mode"
	@echo "  make check       - Run all checks (vet, fmt, lint, test)"
	@echo ""
	@echo "Testing:"
	@echo "  make test        - Run tests"
	@echo "  make coverage    - Generate test coverage report"
	@echo "  make bench       - Run benchmarks"
	@echo ""
	@echo "Building:"
	@echo "  make build       - Build the application"
	@echo "  make build-prod  - Build for production"
	@echo "  make package     - Create release package"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build - Build Docker images"
	@echo "  make docker-up    - Start Docker containers"
	@echo "  make docker-down  - Stop Docker containers"
	@echo ""
	@echo "Database:"
	@echo "  make migrate     - Run database migrations"
	@echo "  make seed        - Seed database with test data"
	@echo "  make backup-db   - Backup database"
	@echo "  make restore-db  - Restore database from backup"
	@echo ""
	@echo "Monitoring:"
	@echo "  make monitor     - Start monitoring"
	@echo "  make dashboard   - Open monitoring dashboard"
	@echo "  make health      - Check service health"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make deps        - Download dependencies"
	@echo "  make fmt         - Format Go code"
	@echo "  make vet         - Run go vet"
	@echo "  make lint        - Run linter"
	@echo ""
	@echo "For more information, see the README.md file."