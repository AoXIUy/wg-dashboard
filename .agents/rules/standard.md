---
trigger: always_on
---

## 🛠 技术栈规范

- **前端核心**：Vue 3 (组合式 API) + HTML5
  
- **后端核心**：Go (≥ v1.21)
  
- **Web 框架 (Go)**：Gin / Fiber 或标准库 `net/http`
  
- **构建工具**：Vite (前端) / `go build` (后端)
  
- **前后端通信**：RESTful API (JSON格式) + Axios / Fetch
  
- **样式处理器**：CSS3 / SASS
  

## 💻 代码规范

### HTML & 模板规范

- **语义化**：必须使用标准的 HTML5 语义化标签（如 `<header>`, `<main>`, `<nav>`, `<section>`），减少无意义的 `<div>` 嵌套。
  
- **属性顺序**：Vue 模板指令优先（如 `v-for`, `v-if`），其次是绑定的属性（`:prop`），原生 HTML 属性（如 `class`, `id`）放在最后。
  
- **可访问性 (A11y)**：HTML 图片必须包含 `alt` 属性，表单元素必须关联 `<label>`。
  

### Vue 前端开发规范

- **组件语法**：统一使用 `<script setup>` 语法糖进行开发。
  
- **逻辑复用**：避免深度嵌套的响应式对象，优先使用组合式函数（Composables）来提取和复用业务逻辑。
  
- **组件通信**：严格遵循“单向数据流”。**禁止直接修改 props**，必须通过 `emit` 将事件派发给父组件处理。
  
- **DOM 操作**：**禁止**使用 `document.getElementById` 等原生原生 API 直接操作 DOM，必须通过 Vue 的 `ref` 进行操作。
  

### Go 后端开发规范

- **命名规范**：包名全小写且为单数；导出变量、函数、结构体使用 `PascalCase`；局部变量使用 `camelCase`。
  
- **错误处理**：必须显式捕获并处理错误（`if err != nil`），**禁止吞掉错误**或在常规 HTTP 请求处理流程中滥用 `panic`。
  
- **请求校验**：处理前端发来的 HTML 表单或 JSON 数据时，必须在结构体中使用 `binding` 或 `validate` 标签进行严格的参数校验。
  
- **并发与安全**：在 HTTP Handler 中启动 Goroutine 时，必须传入请求的副本或使用值传递，避免出现数据竞争（Data Race）。
  

## 📂 项目结构规范

为了保持前后端分离的清晰度，推荐采用标准的目录隔离方式：

- `frontend/`：前端 Vue 项目根目录
  
  - `src/components/`：公共 Vue 组件
    
  - `src/views/`：页面级组件（包含对应的 HTML 结构）
    
  - `src/api/`：封装对 Go 后端的 Axios/Fetch 请求接口
    
  - `src/assets/`：静态资源（图片、全局 CSS/HTML 模板）
    
- `backend/`：Go 后端项目根目录
  
  - `cmd/server/`：Go Web 服务入口文件（`main.go`）
    
  - `internal/handlers/`：HTTP 路由处理逻辑（处理前端请求）
    
  - `internal/models/`：数据模型与数据库操作
    
  - `pkg/`：可复用的 Go 公共工具包
    
- `api/`：前后端接口契约文档（如 OpenAPI/Swagger 配置）
  

## 🚫 禁止事项

1. 禁止在 Vue 的 HTML 模板（`<template>`）中编写复杂的 JavaScript 计算逻辑，必须提取到 `computed` 中。
  
2. 禁止在 Go 的 HTTP Handler 中直接混入复杂的数据库查询逻辑（需抽离到 Service 层或 Model 层）。
  
3. 禁止前后端跨域配置（CORS）过于宽松（如在生产环境中 Go 后端设置 `Access-Control-Allow-Origin: *`）。
  
4. 禁止后端直接将包含敏感字段（如密码、盐值）的数据库模型对象序列化返回给 Vue 前端。
  
5. 禁止在 HTML 结构中使用内联样式（Inline Styles），必须通过类名和 CSS/SASS 文件控制。
  

## ⚠️ 特殊注意事项

1. 保持前端请求的超时时间与 Go 后端接口的 Context 超时时间相匹配，防止前端长期挂起。
  
2. 保留原有的代码注释以及 `console.log` / `log.Println` 等调试输出语句。
  
3. **请勿**将文案和注释中的全角引号（“”）改为半角引号（""）。