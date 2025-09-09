# 过滤系统管理平台

## 项目介绍

**智能黑名单/白名单过滤系统管理平台**是一个基于现代微服务架构构建的企业级数据过滤与安全管控解决方案。系统采用 **Vue 3 + TypeScript** 前端技术栈与 **Go** 高性能后端架构，为企业提供**黑名单过滤**、**空号检测**和**智能限流**三大核心服务能力。

## 技术栈

- **前端框架**: Vue 3 + TypeScript
- **UI组件库**: Element Plus
- **状态管理**: Pinia
- **路由管理**: Vue Router 4
- **HTTP客户端**: Axios
- **构建工具**: Vite
- **图表库**: ECharts
- **样式**: SCSS

## 功能特性

### 🔐 用户认证与权限管理

- **🚪 安全登录系统**：支持用户名密码和第三方登录方式
- **🎫 JWT Token 管理**：自动刷新机制，保障会话安全性
- **🔒 细粒度权限控制**：基于角色的访问控制（RBAC）
- **🛡️ 路由安全守卫**：前端路由拦截，防止未授权访问

### 📊 智能数据仪表板

- **📈 实时统计监控**：系统运行状态和业务数据实时展示
- **📉 可视化图表分析**：多维度数据分析和趋势预测
- **⚡ 性能监控面板**：API 响应时间、成功率等关键指标
- **🔔 智能告警通知**：异常情况自动预警和通知推送

### 🚫 黑名单管理系统

- **📝 多类型数据管理**：手机号码、IP 地址、设备 ID 等
- **⚡ 批量导入导出**：支持 Excel、CSV 格式的批量操作
- **🔍 智能搜索筛选**：多条件组合查询和模糊匹配
- **📋 操作历史追踪**：完整记录数据变更历史和操作人员
- **⏱️ 自动过期管理**：支持设置黑名单有效期和自动清理

### 🔍 智能过滤服务

- **⚡ 单次精确检查**：毫秒级响应的单个数据验证
- **📦 批量高效处理**：支持万级数据批量检测和结果导出
- **📝 详细历史记录**：完整保存检测记录和结果分析
- **🎯 多维度匹配**：支持精确匹配、模糊匹配等多种策略
- **📊 统计分析报告**：检测成功率、拦截率等业务指标

### 📞 空号检测服务

- **🔗 第三方 API 集成**：对接主流运营商查询接口
- **💾 智能结果缓存**：减少重复查询，提升响应效率
- **📊 检测状态统计**：在网、空号、停机等状态分类统计
- **⏰ 定时批量检测**：支持定时任务和批量号码状态更新

### ⚡ 智能限流管理

- **🎛️ 多算法支持**：令牌桶、滑动窗口、计数器等限流算法
- **🔧 灵活配置规则**：支持 IP、用户、接口等多维度限流策略
- **📊 实时监控面板**：限流状态、触发次数等实时数据展示
- **🛠️ 动态规则调整**：运行时动态修改限流参数，无需重启服务

### ⚙️ 系统管理功能

- **👥 用户账户管理**：用户信息维护、角色分配、权限设置
- **📋 系统日志管理**：操作日志查询、错误日志分析
- **🔧 参数配置管理**：系统参数动态配置和实时生效
- **📊 性能监控分析**：系统资源使用情况和性能指标追踪

## 开发环境

### 环境要求
- Node.js >= 16
- npm >= 8

### 安装依赖
```bash
npm install
```

### 启动开发服务器
```bash
npm run dev
```

### 构建生产版本
```bash
npm run build
```

## 项目结构

```
src/
├── api/              # API接口封装
├── assets/           # 静态资源
├── components/       # 公共组件
├── router/           # 路由配置
├── stores/           # Pinia状态管理
├── types/            # TypeScript类型定义
├── utils/            # 工具函数
├── views/            # 页面组件
├── App.vue           # 根组件
└── main.ts           # 入口文件
```

## 部署说明

### 📦 Docker 容器化部署

```bash
# 构建和启动所有服务
docker-compose up -d

# 查看服务运行状态
docker-compose ps

# 查看服务日志
docker-compose logs -f backend
```

### 🔧 生产环境部署

```nginx
# Nginx 反向代理配置
server {
    listen 80;
    server_name your-domain.com;
    
    # 前端静态资源
    location / {
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
    
    # API 接口代理
    location /api/ {
        proxy_pass http://backend:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 📊 监控和日志

```bash
# 查看系统运行状态
curl http://localhost:8080/health

# 查看应用日志
tail -f logs/app.log

# 查看错误日志
tail -f logs/error.log
```

## 接口文档

### 🔐 认证接口

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

### 🔍 过滤检测接口

```http
POST /api/v1/filter/check
Authorization: Bearer <token>
Content-Type: application/json

{
  "phone": "13800138000",
  "ip": "192.168.1.1"
}
```

### 📊 统计查询接口

```http
GET /api/v1/admin/stats
Authorization: Bearer <token>
```

## 技术支持

### 📚 文档资源

- **API 文档**：http://localhost:8080/swagger/
- **用户手册**：详细的功能使用指南
- **开发文档**：技术实现和扩展指南

### 📞 技术支持

- **微信支持**：sz10589067  
- **QQ支持**：10589067
