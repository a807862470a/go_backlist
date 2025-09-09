# 过滤系统管理平台

## 项目介绍

过滤系统管理平台是一个基于 Vue 3 + TypeScript 开发的前端管理系统，用于管理黑名单过滤、空号检测和限流系统。

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

### 核心功能
- ✅ 用户认证系统（登录、登出、路由守卫）
- ✅ 仪表板（统计数据、图表展示、实时监控）
- ✅ 黑名单管理（CRUD、批量导入/导出、搜索筛选）
- ✅ 过滤服务（单个检查、批量检查、历史记录）
- 🚧 空号检测（开发中）
- 🚧 限流管理（开发中）
- 🚧 系统管理（开发中）

### 技术特性
- 🎨 响应式设计，支持移动端
- 🔒 JWT token 认证和自动刷新
- 📊 实时数据统计和图表展示
- 🔄 批量操作支持
- 📱 移动端适配
- 🎯 TypeScript 严格类型检查
- 🚀 高性能构建和优化

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

### 静态部署
1. 构建项目：`npm run build`
2. 将 `dist` 目录下的文件部署到 Web 服务器

### Docker 部署
```dockerfile
FROM nginx:alpine
COPY dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```
