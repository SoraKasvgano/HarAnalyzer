# 🚀 Universal HAR Analyzer User Guide

## 📋 Feature Overview

The Universal HAR Analyzer is a simple tool that can automatically analyze any HAR (HTTP Archive) file, extract useful information, and generate detailed analysis reports and code templates.

## ✨ Main Features

### 🔍 Automatic Discovery and Analysis
- **Auto Scanning**: Scans all `.har` files in the current directory
- **Batch Processing**: Supports analyzing multiple HAR files simultaneously
- **Smart Parsing**: Automatically handles various HAR file formats and versions

### 📊 Detailed Statistical Analysis
- **Request Statistics**: Total requests, time span, browser information
- **Host Analysis**: Unique host count, request distribution per host
- **API Popularity**: API endpoints sorted by call frequency
- **Parameter Extraction**: Automatically extracts all request parameters and occurrence frequency
- **Request Header Analysis**: Common request header statistics and importance analysis
- **Response Types**: Distribution of JSON, HTML, images, and other response types
- **Status Code Statistics**: HTTP status code distribution

### 💻 Code Template Generation
- **Go Structs**: Automatically generates API response structs
- **Header Setup**: Generates Go code for common request headers
- **API Endpoint List**: Organizes all API endpoints for reference

## 🎯 Usage Instructions

### 1. Basic Usage
```bash
# Place HAR files in the same directory as the program
# Run the analyzer
./universal_har_analyzer.exe
```

### 2. File Preparation
- Place the `.har` files to be analyzed in the program root directory
- Supports analyzing multiple HAR files simultaneously
- File names can be arbitrary, the program will automatically recognize them

### 3. Output Results
The program will generate the following in the `universal_har_analysis` directory:
- `*_analysis_*.json`: Structured analysis data
- `*_report_*.md`: Human-readable analysis reports
- `summary_report.md`: Summary report

## 📈 Analysis Result Examples

### Basic Information
```
- Total Requests: 63
- Unique Hosts: 1
- Time Span: 15:08:36 - 16:04:33 (55.9 minutes)
- Browser: Chrome 108.0.0.0
- HAR Version: 1.2
```

### Popular APIs
```
POST /api/tdmp/statis/findList (49 calls)
POST /api/tdmp/dictionary/findByType (12 calls)
```

### Common Parameters
```
page: 50 times
size: 50 times
type: 49 times
condition: 16 times
```

### Generated Go Code Templates
```go
// Basic response struct
type APIResponse struct {
    Code    int         `json:"code"`
    Message string      `json:"message"`
    Data    interface{} `json:"data"`
}

// Header setup
req.Header.Set("Authorization", "your_token_here") // Appears 62 times
req.Header.Set("Content-Type", "application/json") // Appears 62 times
req.Header.Set("User-Agent", "Mozilla/5.0...") // Appears 62 times
```

## 🔧 Advanced Features

### Smart Parameter Extraction
- **JSON Parameters**: Automatically parses JSON parameters in POST requests
- **Query Parameters**: Extracts URL query string parameters
- **Form Parameters**: Parses form submission parameters
- **Nested Parameters**: Supports multi-level nested JSON parameter extraction

### Smart Request Header Analysis
The program automatically identifies important request headers:
- Authentication related: `Authorization`, `Cookie`, `Token`
- Content related: `Content-Type`, `Accept`
- Browser related: `User-Agent`, `Referer`, `Origin`
- Security related: `X-CSRF-Token`, `X-API-Key`

### Response Type Classification
- **JSON**: API response data
- **HTML**: Web page content
- **JavaScript**: Script files
- **CSS**: Style files
- **Image**: Image resources
- **Other**: Other types

## 📁 Output File Description

### JSON Analysis File (`*_analysis_*.json`)
Contains complete structured data:
```json
{
  "metadata": {
    "fileName": "example.har",
    "totalRequests": 63,
    "uniqueHosts": 1,
    "timeSpan": "15:08:36 - 16:04:33 (55.9 minutes)"
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

### Markdown Report (`*_report_*.md`)
Human-readable detailed analysis report, including:
- 📊 Basic information statistics
- 🌐 Host and API analysis
- 📝 Parameter and request header statistics
- 💻 Copy-paste ready code templates

### Summary Report (`summary_report.md`)
Summary information and usage instructions for multi-file analysis.

## 🎨 Practical Application Scenarios

### 1. API Reverse Engineering
- Analyze website API call patterns
- Extract API endpoints and parameters
- Generate corresponding client code

### 2. Performance Analysis
- Analyze request frequency and time distribution
- Identify high-frequency API calls
- Optimize request strategies

### 3. Security Auditing
- Check for sensitive information leakage
- Analyze authentication mechanisms
- Identify potential security issues

### 4. Development Assistance
- Quickly understand third-party APIs
- Generate test code templates
- Document API interfaces

## 🚀 Technical Features

### Highly Universal
- Supports any file compliant with HAR 1.2 standard
- Automatically adapts to different data formats
- Intelligently handles various edge cases

### Smart Analysis
- Automatically identifies important parameters and request headers
- Intelligently categorizes response types
- Sorts analysis results by importance

### Code Generation
- Generates directly usable Go code
- Includes detailed comments and usage instructions
- Supports copy-paste direct usage

## 📝 Usage Recommendations

1. **File Naming**: Use meaningful HAR file names for easy identification of analysis results
2. **Batch Analysis**: Multiple HAR files can be placed simultaneously for batch analysis
3. **Result Utilization**: JSON files are suitable for program processing, Markdown files for manual review
4. **Code Reuse**: Generated code templates can be directly copied to projects

## 🎯 Summary

The Universal HAR Analyzer is an easy-to-use tool that can:
- ✅ Automatically analyze any HAR file
- ✅ Generate detailed statistical reports
- ✅ Provide usable code templates
- ✅ Support batch processing
- ✅ Output results in multiple formats
