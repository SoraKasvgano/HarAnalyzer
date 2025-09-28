# HarAnalyzer
HAR Analyzer is a tool used to analyze HAR (HTTP Archive) files, which capture a comprehensive record of web requests and responses. These files are essential for debugging and analyzing web traffic, allowing users to see network performance and troubleshoot front-end issues. 

# 🚀 通用HAR分析器使用说明

## 📋 功能概述

通用HAR分析器是一个的工具，可以自动分析任何HAR（HTTP Archive）文件，提取有用的信息并生成详细的分析报告和代码模板。

## ✨ 主要功能

### 🔍 自动发现和分析
- **自动扫描**：扫描当前目录下的所有`.har`文件
- **批量处理**：支持同时分析多个HAR文件
- **智能解析**：自动处理各种HAR文件格式和版本

### 📊 详细统计分析
- **请求统计**：总请求数、时间跨度、浏览器信息
- **主机分析**：唯一主机数、每个主机的请求分布
- **API热度**：按调用次数排序的API端点
- **参数提取**：自动提取所有请求参数和出现频率
- **请求头分析**：常用请求头统计和重要性分析
- **响应类型**：JSON、HTML、图片等响应类型分布
- **状态码统计**：HTTP状态码分布情况

### 💻 代码模板生成
- **Go结构体**：自动生成API响应结构体
- **请求头设置**：生成常用请求头的Go代码
- **API端点列表**：整理所有API端点供参考

## 🎯 使用方法

### 1. 基本使用
```bash
# 将HAR文件放在程序同目录下
# 运行分析器
./universal_har_analyzer.exe
```

### 2. 文件准备
- 将需要分析的`.har`文件放在程序根目录
- 支持多个HAR文件同时分析
- 文件名可以任意，程序会自动识别

### 3. 输出结果
程序会在`universal_har_analysis`目录下生成：
- `*_analysis_*.json`：结构化分析数据
- `*_report_*.md`：人类可读的分析报告
- `summary_report.md`：汇总报告

## 📈 分析结果示例

### 基本信息
```
- 总请求数: 63
- 唯一主机数: 1
- 时间跨度: 15:08:36 - 16:04:33 (55.9分钟)
- 浏览器: Chrome 108.0.0.0
- HAR版本: 1.2
```

### 热门API
```
POST /api/tdmp/statis/findList (调用49次)
POST /api/tdmp/dictionary/findByType (调用12次)
```

### 常用参数
```
page: 50次
size: 50次
type: 49次
condition: 16次
```

### 生成的Go代码模板
```go
// 基础响应结构体
type APIResponse struct {
    Code    int         `json:"code"`
    Message string      `json:"message"`
    Data    interface{} `json:"data"`
}

// 请求头设置
req.Header.Set("Authorization", "your_token_here") // 出现62次
req.Header.Set("Content-Type", "application/json") // 出现62次
req.Header.Set("User-Agent", "Mozilla/5.0...") // 出现62次
```

## 🔧 高级功能

### 智能参数提取
- **JSON参数**：自动解析POST请求中的JSON参数
- **查询参数**：提取URL查询字符串参数
- **表单参数**：解析表单提交的参数
- **嵌套参数**：支持多层嵌套的JSON参数提取

### 请求头智能分析
程序会自动识别重要的请求头：
- 认证相关：`Authorization`、`Cookie`、`Token`
- 内容相关：`Content-Type`、`Accept`
- 浏览器相关：`User-Agent`、`Referer`、`Origin`
- 安全相关：`X-CSRF-Token`、`X-API-Key`

### 响应类型分类
- **JSON**：API响应数据
- **HTML**：网页内容
- **JavaScript**：脚本文件
- **CSS**：样式文件
- **Image**：图片资源
- **Other**：其他类型

## 📁 输出文件说明

### JSON分析文件 (`*_analysis_*.json`)
包含完整的结构化数据：
```json
{
  "metadata": {
    "fileName": "example.har",
    "totalRequests": 63,
    "uniqueHosts": 1,
    "timeSpan": "15:08:36 - 16:04:33 (55.9分钟)"
  },
  "extractedData": {
    "parameters": {"page": 50, "size": 50},
    "headers": {"Authorization": 62, "Content-Type": 62},
    "methods": {"POST": 61, "GET": 2}
  },
  "codeTemplates": {
    "goStructs": ["type APIResponse struct {...}"],
    "headers": ["req.Header.Set(...)"],
    "apiEndpoints": ["// POST /api/endpoint"]
  }
}
```

### Markdown报告 (`*_report_*.md`)
人类可读的详细分析报告，包含：
- 📊 基本信息统计
- 🌐 主机和API分析
- 📝 参数和请求头统计
- 💻 可复制的代码模板

### 汇总报告 (`summary_report.md`)
多文件分析的汇总信息和使用说明。

## 🎨 实际应用场景

### 1. API逆向工程
- 分析网站的API调用模式
- 提取API端点和参数
- 生成对应的客户端代码

### 2. 性能分析
- 分析请求频率和时间分布
- 识别高频API调用
- 优化请求策略

### 3. 安全审计
- 检查敏感信息泄露
- 分析认证机制
- 识别潜在的安全问题

### 4. 开发辅助
- 快速了解第三方API
- 生成测试用的代码模板
- 文档化API接口

## 🚀 技术特点

### 高度通用
- 支持任何符合HAR 1.2标准的文件
- 自动适应不同的数据格式
- 智能处理各种边界情况

### 智能分析
- 自动识别重要参数和请求头
- 智能分类响应类型
- 按重要性排序分析结果

### 代码生成
- 生成可直接使用的Go代码
- 包含详细的注释和使用说明
- 支持复制粘贴直接使用

## 📝 使用建议

1. **文件命名**：使用有意义的HAR文件名，便于识别分析结果
2. **批量分析**：可以同时放置多个HAR文件进行批量分析
3. **结果利用**：JSON文件适合程序处理，Markdown文件适合人工查看
4. **代码复用**：生成的代码模板可以直接复制到项目中使用

## 🎯 总结

通用HAR分析器是一个使用简单的工具，能够：
- ✅ 自动分析任何HAR文件
- ✅ 生成详细的统计报告
- ✅ 提供可用的代码模板
- ✅ 支持批量处理
- ✅ 输出多种格式的结果

