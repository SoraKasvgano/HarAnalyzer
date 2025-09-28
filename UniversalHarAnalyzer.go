package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 通用HAR文件结构
type UniversalHARFile struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Browser struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"browser"`
		Pages []struct {
			StartedDateTime string `json:"startedDateTime"`
			ID              string `json:"id"`
			Title           string `json:"title"`
			PageTimings     struct {
				OnContentLoad float64 `json:"onContentLoad"`
				OnLoad        float64 `json:"onLoad"`
			} `json:"pageTimings"`
		} `json:"pages"`
		Entries []struct {
			StartedDateTime string  `json:"startedDateTime"`
			Time            float64 `json:"time"`
			Request         struct {
				Method      string `json:"method"`
				URL         string `json:"url"`
				HTTPVersion string `json:"httpVersion"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				QueryString []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"queryString"`
				PostData struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				} `json:"postData"`
				HeadersSize float64 `json:"headersSize"`
				BodySize    float64 `json:"bodySize"`
			} `json:"request"`
			Response struct {
				Status      int    `json:"status"`
				StatusText  string `json:"statusText"`
				HTTPVersion string `json:"httpVersion"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				Content struct {
					Size     float64 `json:"size"`
					MimeType string  `json:"mimeType"`
					Text     string  `json:"text"`
				} `json:"content"`
				RedirectURL string  `json:"redirectURL"`
				HeadersSize float64 `json:"headersSize"`
				BodySize    float64 `json:"bodySize"`
			} `json:"response"`
			Cache struct {
				BeforeRequest interface{} `json:"beforeRequest"`
				AfterRequest  interface{} `json:"afterRequest"`
			} `json:"cache"`
			Timings struct {
				Blocked float64 `json:"blocked"`
				DNS     float64 `json:"dns"`
				Connect float64 `json:"connect"`
				Send    float64 `json:"send"`
				Wait    float64 `json:"wait"`
				Receive float64 `json:"receive"`
				SSL     float64 `json:"ssl"`
			} `json:"timings"`
		} `json:"entries"`
	} `json:"log"`
}

// 通用分析结果
type UniversalAnalysisResult struct {
	Metadata struct {
		FileName      string    `json:"fileName"`
		AnalysisTime  time.Time `json:"analysisTime"`
		TotalRequests int       `json:"totalRequests"`
		UniqueHosts   int       `json:"uniqueHosts"`
		TimeSpan      string    `json:"timeSpan"`
		BrowserInfo   string    `json:"browserInfo"`
		HARVersion    string    `json:"harVersion"`
	} `json:"metadata"`

	Hosts []HostInfo `json:"hosts"`
	APIs  []APIInfo  `json:"apis"`

	// 数据提取结果
	ExtractedData struct {
		Parameters    map[string]int `json:"parameters"`    // 参数名及出现次数
		Headers       map[string]int `json:"headers"`       // 请求头及出现次数
		ResponseTypes map[string]int `json:"responseTypes"` // 响应类型及出现次数
		StatusCodes   map[string]int `json:"statusCodes"`   // 状态码及出现次数
		Methods       map[string]int `json:"methods"`       // HTTP方法及出现次数
		ContentTypes  map[string]int `json:"contentTypes"`  // 内容类型及出现次数
	} `json:"extractedData"`

	// 自动生成的代码模板
	CodeTemplates struct {
		GoStructs    []string `json:"goStructs"`    // Go结构体定义
		APIEndpoints []string `json:"apiEndpoints"` // API端点列表
		Headers      []string `json:"headers"`      // 常用请求头
	} `json:"codeTemplates"`
}

type HostInfo struct {
	Host         string   `json:"host"`
	RequestCount int      `json:"requestCount"`
	Methods      []string `json:"methods"`
	Paths        []string `json:"paths"`
}

type APIInfo struct {
	Method       string                 `json:"method"`
	URL          string                 `json:"url"`
	Host         string                 `json:"host"`
	Path         string                 `json:"path"`
	Parameters   map[string]interface{} `json:"parameters"`
	Headers      map[string]string      `json:"headers"`
	ResponseType string                 `json:"responseType"`
	StatusCode   int                    `json:"statusCode"`
	CallCount    int                    `json:"callCount"`
}

// 通用HAR分析器
type UniversalHARAnalyzer struct {
	outputDir string
}

// 创建新的通用分析器
func NewUniversalHARAnalyzer() *UniversalHARAnalyzer {
	return &UniversalHARAnalyzer{
		outputDir: "universal_har_analysis",
	}
}

// 扫描目录下的所有HAR文件
func (ua *UniversalHARAnalyzer) ScanHARFiles(dir string) ([]string, error) {
	var harFiles []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".har") {
			harFiles = append(harFiles, path)
		}

		return nil
	})

	return harFiles, err
}

// 分析单个HAR文件
func (ua *UniversalHARAnalyzer) AnalyzeHARFile(filePath string) (*UniversalAnalysisResult, error) {
	fmt.Printf("📁 分析HAR文件: %s\n", filepath.Base(filePath))

	// 读取HAR文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取HAR文件失败: %w", err)
	}

	var harFile UniversalHARFile
	if err := json.Unmarshal(data, &harFile); err != nil {
		return nil, fmt.Errorf("解析HAR文件失败: %w", err)
	}

	// 初始化分析结果
	result := &UniversalAnalysisResult{}
	result.Metadata.FileName = filepath.Base(filePath)
	result.Metadata.AnalysisTime = time.Now()
	result.Metadata.TotalRequests = len(harFile.Log.Entries)
	result.Metadata.HARVersion = harFile.Log.Version
	result.Metadata.BrowserInfo = fmt.Sprintf("%s %s", harFile.Log.Browser.Name, harFile.Log.Browser.Version)

	// 初始化数据统计
	result.ExtractedData.Parameters = make(map[string]int)
	result.ExtractedData.Headers = make(map[string]int)
	result.ExtractedData.ResponseTypes = make(map[string]int)
	result.ExtractedData.StatusCodes = make(map[string]int)
	result.ExtractedData.Methods = make(map[string]int)
	result.ExtractedData.ContentTypes = make(map[string]int)

	hostMap := make(map[string]*HostInfo)
	apiMap := make(map[string]*APIInfo)

	// 分析每个请求
	var startTime, endTime time.Time
	for i, entry := range harFile.Log.Entries {
		// 解析时间
		if entryTime, err := time.Parse(time.RFC3339, entry.StartedDateTime); err == nil {
			if i == 0 || entryTime.Before(startTime) {
				startTime = entryTime
			}
			if i == 0 || entryTime.After(endTime) {
				endTime = entryTime
			}
		}

		// 解析URL
		url := entry.Request.URL
		method := entry.Request.Method

		// 提取主机信息
		if host := ua.extractHost(url); host != "" {
			if _, exists := hostMap[host]; !exists {
				hostMap[host] = &HostInfo{
					Host:    host,
					Methods: []string{},
					Paths:   []string{},
				}
			}
			hostMap[host].RequestCount++
			ua.addUniqueString(&hostMap[host].Methods, method)
			ua.addUniqueString(&hostMap[host].Paths, ua.extractPath(url))
		}

		// 统计HTTP方法
		result.ExtractedData.Methods[method]++

		// 统计状态码
		statusCode := fmt.Sprintf("%d", entry.Response.Status)
		result.ExtractedData.StatusCodes[statusCode]++

		// 分析请求头
		for _, header := range entry.Request.Headers {
			result.ExtractedData.Headers[header.Name]++
		}

		// 分析查询参数
		for _, param := range entry.Request.QueryString {
			result.ExtractedData.Parameters[param.Name]++
		}

		// 分析POST数据中的参数
		if entry.Request.PostData.Text != "" {
			ua.extractPostParameters(entry.Request.PostData.Text, result.ExtractedData.Parameters)
		}

		// 分析响应类型
		contentType := entry.Response.Content.MimeType
		if contentType != "" {
			result.ExtractedData.ContentTypes[contentType]++
			result.ExtractedData.ResponseTypes[ua.simplifyContentType(contentType)]++
		}

		// 创建API信息
		apiKey := fmt.Sprintf("%s %s", method, ua.extractPath(url))
		if _, exists := apiMap[apiKey]; !exists {
			apiMap[apiKey] = &APIInfo{
				Method:       method,
				URL:          url,
				Host:         ua.extractHost(url),
				Path:         ua.extractPath(url),
				Parameters:   make(map[string]interface{}),
				Headers:      make(map[string]string),
				ResponseType: ua.simplifyContentType(contentType),
				StatusCode:   entry.Response.Status,
				CallCount:    0,
			}

			// 收集参数
			for _, param := range entry.Request.QueryString {
				apiMap[apiKey].Parameters[param.Name] = param.Value
			}

			// 收集重要请求头
			for _, header := range entry.Request.Headers {
				if ua.isImportantHeader(header.Name) {
					apiMap[apiKey].Headers[header.Name] = header.Value
				}
			}
		}
		apiMap[apiKey].CallCount++
	}

	// 转换map为slice
	for _, host := range hostMap {
		result.Hosts = append(result.Hosts, *host)
	}
	for _, api := range apiMap {
		result.APIs = append(result.APIs, *api)
	}

	// 排序
	sort.Slice(result.Hosts, func(i, j int) bool {
		return result.Hosts[i].RequestCount > result.Hosts[j].RequestCount
	})
	sort.Slice(result.APIs, func(i, j int) bool {
		return result.APIs[i].CallCount > result.APIs[j].CallCount
	})

	// 设置时间跨度
	result.Metadata.UniqueHosts = len(hostMap)
	if !startTime.IsZero() && !endTime.IsZero() {
		result.Metadata.TimeSpan = fmt.Sprintf("%s - %s (%.1f分钟)",
			startTime.Format("15:04:05"),
			endTime.Format("15:04:05"),
			endTime.Sub(startTime).Minutes())
	}

	// 生成代码模板
	ua.generateCodeTemplates(result)

	return result, nil
}

// 提取主机名
func (ua *UniversalHARAnalyzer) extractHost(url string) string {
	re := regexp.MustCompile(`https?://([^/]+)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// 提取路径
func (ua *UniversalHARAnalyzer) extractPath(url string) string {
	re := regexp.MustCompile(`https?://[^/]+(/[^?#]*)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		return matches[1]
	}
	return "/"
}

// 添加唯一字符串到切片
func (ua *UniversalHARAnalyzer) addUniqueString(slice *[]string, str string) {
	for _, existing := range *slice {
		if existing == str {
			return
		}
	}
	*slice = append(*slice, str)
}

// 提取POST参数
func (ua *UniversalHARAnalyzer) extractPostParameters(postData string, params map[string]int) {
	// 尝试解析JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(postData), &jsonData); err == nil {
		ua.extractJSONKeys(jsonData, "", params)
		return
	}

	// 尝试解析表单数据
	if strings.Contains(postData, "=") && strings.Contains(postData, "&") {
		pairs := strings.Split(postData, "&")
		for _, pair := range pairs {
			if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
				params[kv[0]]++
			}
		}
	}
}

// 递归提取JSON键
func (ua *UniversalHARAnalyzer) extractJSONKeys(data interface{}, prefix string, params map[string]int) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			params[fullKey]++
			ua.extractJSONKeys(value, fullKey, params)
		}
	case []interface{}:
		for i, item := range v {
			indexKey := fmt.Sprintf("%s[%d]", prefix, i)
			ua.extractJSONKeys(item, indexKey, params)
		}
	}
}

// 简化内容类型
func (ua *UniversalHARAnalyzer) simplifyContentType(contentType string) string {
	if strings.Contains(contentType, "json") {
		return "JSON"
	}
	if strings.Contains(contentType, "html") {
		return "HTML"
	}
	if strings.Contains(contentType, "xml") {
		return "XML"
	}
	if strings.Contains(contentType, "javascript") {
		return "JavaScript"
	}
	if strings.Contains(contentType, "css") {
		return "CSS"
	}
	if strings.Contains(contentType, "image") {
		return "Image"
	}
	if strings.Contains(contentType, "text") {
		return "Text"
	}
	return "Other"
}

// 判断是否为重要请求头
func (ua *UniversalHARAnalyzer) isImportantHeader(headerName string) bool {
	important := []string{
		"authorization", "cookie", "content-type", "accept",
		"user-agent", "referer", "origin", "x-requested-with",
		"x-csrf-token", "x-api-key", "bearer", "token",
	}

	headerLower := strings.ToLower(headerName)
	for _, imp := range important {
		if strings.Contains(headerLower, imp) {
			return true
		}
	}
	return false
}

// 生成代码模板
func (ua *UniversalHARAnalyzer) generateCodeTemplates(result *UniversalAnalysisResult) {
	// 生成Go结构体
	result.CodeTemplates.GoStructs = ua.generateGoStructs(result)

	// 生成API端点列表
	result.CodeTemplates.APIEndpoints = ua.generateAPIEndpoints(result)

	// 生成常用请求头
	result.CodeTemplates.Headers = ua.generateCommonHeaders(result)
}

// 生成Go结构体
func (ua *UniversalHARAnalyzer) generateGoStructs(result *UniversalAnalysisResult) []string {
	var structs []string

	// 基础响应结构体
	structs = append(structs, `type APIResponse struct {
	Code    int         `+"`json:\"code\"`"+`
	Message string      `+"`json:\"message\"`"+`
	Data    interface{} `+"`json:\"data\"`"+`
}`)

	// 分页响应结构体
	structs = append(structs, `type PagedResponse struct {
	Content       []interface{} `+"`json:\"content\"`"+`
	TotalElements int           `+"`json:\"totalElements\"`"+`
	TotalPages    int           `+"`json:\"totalPages\"`"+`
	Size          int           `+"`json:\"size\"`"+`
	Number        int           `+"`json:\"number\"`"+`
}`)

	return structs
}

// 生成API端点列表
func (ua *UniversalHARAnalyzer) generateAPIEndpoints(result *UniversalAnalysisResult) []string {
	var endpoints []string

	for _, api := range result.APIs {
		if api.CallCount > 1 { // 只包含调用次数大于1的API
			endpoint := fmt.Sprintf("// %s %s (调用%d次)", api.Method, api.Path, api.CallCount)
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// 生成常用请求头
func (ua *UniversalHARAnalyzer) generateCommonHeaders(result *UniversalAnalysisResult) []string {
	var headers []string

	// 按出现频率排序
	type headerCount struct {
		name  string
		count int
	}

	var headerCounts []headerCount
	for name, count := range result.ExtractedData.Headers {
		if count > 1 && ua.isImportantHeader(name) {
			headerCounts = append(headerCounts, headerCount{name, count})
		}
	}

	sort.Slice(headerCounts, func(i, j int) bool {
		return headerCounts[i].count > headerCounts[j].count
	})

	for _, hc := range headerCounts {
		headers = append(headers, fmt.Sprintf("req.Header.Set(\"%s\", \"your_value_here\") // 出现%d次", hc.name, hc.count))
	}

	return headers
}

// 批量分析所有HAR文件
func (ua *UniversalHARAnalyzer) AnalyzeAllHARFiles(dir string) error {
	// 创建输出目录
	if err := os.MkdirAll(ua.outputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 扫描HAR文件
	harFiles, err := ua.ScanHARFiles(dir)
	if err != nil {
		return fmt.Errorf("扫描HAR文件失败: %w", err)
	}

	if len(harFiles) == 0 {
		fmt.Println("❌ 未找到HAR文件")
		return nil
	}

	fmt.Printf("🔍 发现 %d 个HAR文件\n", len(harFiles))

	// 分析每个文件
	for i, filePath := range harFiles {
		fmt.Printf("\n[%d/%d] ", i+1, len(harFiles))

		result, err := ua.AnalyzeHARFile(filePath)
		if err != nil {
			fmt.Printf("❌ 分析失败: %v\n", err)
			continue
		}

		// 保存分析结果
		if err := ua.saveAnalysisResult(result); err != nil {
			fmt.Printf("⚠️ 保存结果失败: %v\n", err)
		} else {
			fmt.Printf("✅ 分析完成: %d个请求, %d个主机, %d个API\n",
				result.Metadata.TotalRequests,
				result.Metadata.UniqueHosts,
				len(result.APIs))
		}
	}

	// 生成汇总报告
	if err := ua.generateSummaryReport(harFiles); err != nil {
		fmt.Printf("⚠️ 生成汇总报告失败: %v\n", err)
	}

	fmt.Printf("\n🎉 分析完成! 结果保存在: %s\n", ua.outputDir)
	return nil
}

// 保存分析结果
func (ua *UniversalHARAnalyzer) saveAnalysisResult(result *UniversalAnalysisResult) error {
	timestamp := time.Now().Unix()

	// 保存JSON结果
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	jsonFile := filepath.Join(ua.outputDir, fmt.Sprintf("%s_analysis_%d.json",
		strings.TrimSuffix(result.Metadata.FileName, ".har"), timestamp))

	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		return err
	}

	// 生成Markdown报告
	if err := ua.generateMarkdownReport(result, timestamp); err != nil {
		return err
	}

	return nil
}

// 生成Markdown报告
func (ua *UniversalHARAnalyzer) generateMarkdownReport(result *UniversalAnalysisResult, timestamp int64) error {
	var report strings.Builder

	report.WriteString(fmt.Sprintf("# HAR分析报告: %s\n\n", result.Metadata.FileName))
	report.WriteString(fmt.Sprintf("**分析时间**: %s\n\n", result.Metadata.AnalysisTime.Format("2006-01-02 15:04:05")))

	// 基本信息
	report.WriteString("## 📊 基本信息\n\n")
	report.WriteString(fmt.Sprintf("- **总请求数**: %d\n", result.Metadata.TotalRequests))
	report.WriteString(fmt.Sprintf("- **唯一主机数**: %d\n", result.Metadata.UniqueHosts))
	report.WriteString(fmt.Sprintf("- **时间跨度**: %s\n", result.Metadata.TimeSpan))
	report.WriteString(fmt.Sprintf("- **浏览器**: %s\n", result.Metadata.BrowserInfo))
	report.WriteString(fmt.Sprintf("- **HAR版本**: %s\n\n", result.Metadata.HARVersion))

	// 主机统计
	report.WriteString("## 🌐 主机统计\n\n")
	report.WriteString("| 主机 | 请求数 | HTTP方法 |\n")
	report.WriteString("|------|--------|----------|\n")
	for _, host := range result.Hosts {
		methods := strings.Join(host.Methods, ", ")
		report.WriteString(fmt.Sprintf("| %s | %d | %s |\n", host.Host, host.RequestCount, methods))
	}
	report.WriteString("\n")

	// API统计
	report.WriteString("## 🔗 热门API (调用次数 > 1)\n\n")
	report.WriteString("| 方法 | 路径 | 主机 | 调用次数 | 响应类型 |\n")
	report.WriteString("|------|------|------|----------|----------|\n")
	for _, api := range result.APIs {
		if api.CallCount > 1 {
			report.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s |\n",
				api.Method, api.Path, api.Host, api.CallCount, api.ResponseType))
		}
	}
	report.WriteString("\n")

	// 参数统计
	report.WriteString("## 📝 常用参数 (出现次数 > 1)\n\n")
	ua.writeTopItems(&report, result.ExtractedData.Parameters, "参数名", "出现次数")

	// 请求头统计
	report.WriteString("## 📋 常用请求头 (出现次数 > 5)\n\n")
	ua.writeTopItemsFiltered(&report, result.ExtractedData.Headers, "请求头", "出现次数", 5)

	// HTTP方法统计
	report.WriteString("## 🔧 HTTP方法统计\n\n")
	ua.writeTopItems(&report, result.ExtractedData.Methods, "方法", "使用次数")

	// 状态码统计
	report.WriteString("## 📈 状态码统计\n\n")
	ua.writeTopItems(&report, result.ExtractedData.StatusCodes, "状态码", "出现次数")

	// 响应类型统计
	report.WriteString("## 📄 响应类型统计\n\n")
	ua.writeTopItems(&report, result.ExtractedData.ResponseTypes, "类型", "出现次数")

	// 代码模板
	report.WriteString("## 💻 代码模板\n\n")

	report.WriteString("### Go结构体\n\n")
	for _, goStruct := range result.CodeTemplates.GoStructs {
		report.WriteString("```go\n")
		report.WriteString(goStruct)
		report.WriteString("\n```\n\n")
	}

	report.WriteString("### 常用请求头设置\n\n")
	report.WriteString("```go\n")
	for _, header := range result.CodeTemplates.Headers {
		report.WriteString(header + "\n")
	}
	report.WriteString("```\n\n")

	report.WriteString("### API端点列表\n\n")
	report.WriteString("```go\n")
	for _, endpoint := range result.CodeTemplates.APIEndpoints {
		report.WriteString(endpoint + "\n")
	}
	report.WriteString("```\n\n")

	// 保存报告
	reportFile := filepath.Join(ua.outputDir, fmt.Sprintf("%s_report_%d.md",
		strings.TrimSuffix(result.Metadata.FileName, ".har"), timestamp))

	return os.WriteFile(reportFile, []byte(report.String()), 0644)
}

// 写入排序后的统计项
func (ua *UniversalHARAnalyzer) writeTopItems(report *strings.Builder, items map[string]int, nameHeader, countHeader string) {
	ua.writeTopItemsFiltered(report, items, nameHeader, countHeader, 1)
}

// 写入过滤后的排序统计项
func (ua *UniversalHARAnalyzer) writeTopItemsFiltered(report *strings.Builder, items map[string]int, nameHeader, countHeader string, minCount int) {
	type item struct {
		name  string
		count int
	}

	var sortedItems []item
	for name, count := range items {
		if count > minCount {
			sortedItems = append(sortedItems, item{name, count})
		}
	}

	sort.Slice(sortedItems, func(i, j int) bool {
		return sortedItems[i].count > sortedItems[j].count
	})

	if len(sortedItems) == 0 {
		report.WriteString("无数据\n\n")
		return
	}

	report.WriteString(fmt.Sprintf("| %s | %s |\n", nameHeader, countHeader))
	report.WriteString("|------|------|\n")

	maxItems := 20 // 最多显示20项
	for i, item := range sortedItems {
		if i >= maxItems {
			report.WriteString(fmt.Sprintf("| ... | ... |\n"))
			report.WriteString(fmt.Sprintf("| **总计**: %d项 | |\n", len(sortedItems)))
			break
		}
		report.WriteString(fmt.Sprintf("| %s | %d |\n", item.name, item.count))
	}
	report.WriteString("\n")
}

// 生成汇总报告
func (ua *UniversalHARAnalyzer) generateSummaryReport(harFiles []string) error {
	var summary strings.Builder

	summary.WriteString("# 通用HAR分析汇总报告\n\n")
	summary.WriteString(fmt.Sprintf("**生成时间**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	summary.WriteString(fmt.Sprintf("**分析文件数**: %d\n\n", len(harFiles)))

	summary.WriteString("## 📁 分析的文件列表\n\n")
	for i, file := range harFiles {
		summary.WriteString(fmt.Sprintf("%d. %s\n", i+1, filepath.Base(file)))
	}
	summary.WriteString("\n")

	summary.WriteString("## 📋 使用说明\n\n")
	summary.WriteString("1. 每个HAR文件都生成了对应的JSON分析结果和Markdown报告\n")
	summary.WriteString("2. JSON文件包含完整的结构化数据，可用于程序处理\n")
	summary.WriteString("3. Markdown报告提供人类可读的分析结果\n")
	summary.WriteString("4. 代码模板可以直接复制使用\n\n")

	summary.WriteString("## 🔧 生成的文件说明\n\n")
	summary.WriteString("- `*_analysis_*.json`: 结构化分析数据\n")
	summary.WriteString("- `*_report_*.md`: 可读性分析报告\n")
	summary.WriteString("- `summary_report.md`: 本汇总报告\n\n")

	summaryFile := filepath.Join(ua.outputDir, "summary_report.md")
	return os.WriteFile(summaryFile, []byte(summary.String()), 0644)
}

func main() {
	fmt.Println("🚀 通用HAR分析器启动")
	fmt.Println("====================")

	analyzer := NewUniversalHARAnalyzer()

	// 分析当前目录下的所有HAR文件
	currentDir, _ := os.Getwd()

	if err := analyzer.AnalyzeAllHARFiles(currentDir); err != nil {
		fmt.Printf("❌ 分析失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n🎯 分析完成!")
	fmt.Printf("📂 查看结果: %s\n", analyzer.outputDir)
}
