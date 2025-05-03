<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ page import="java.sql.*" %>
<%@ page import="org.json.JSONObject" %>
<%@ page import="phishing.GeminiPhishingAnalyzer" %>
<%@ page import="phishing.PythonBridge1" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.concurrent.*" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="java.io.File" %>

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Admin - URL Phishing Analysis Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .analysis-content {
                white-space: pre-wrap;
                line-height: 1.5;
            }
            .analysis-content h3 {
                margin-top: 1rem;
                font-size: 1.2rem;
                font-weight: bold;
            }
            .analysis-content ul {
                padding-left: 1.5rem;
            }
            .highlight {
                background-color: #f8f9fa;
                padding: 1rem;
                border-radius: 0.25rem;
                margin-bottom: 1rem;
            }
            .card {
                margin-bottom: 1.5rem;
            }
            .url-info {
                margin-bottom: 0.5rem;
            }
            .status-safe {
                color: green;
                font-weight: bold;
            }
            .status-phishing {
                color: red;
                font-weight: bold;
            }
            .dashboard-header {
                background-color: #343a40;
                color: white;
                padding: 1rem;
                margin-bottom: 2rem;
            }
            .refresh-container {
                text-align: right;
                margin-bottom: 1rem;
            }
            .loading {
                text-align: center;
                padding: 2rem;
            }
            .debug-info {
                font-family: monospace;
                font-size: 0.8rem;
                padding: 0.5rem;
                background-color: #f8f9fa;
                border: 1px solid #ddd;
                max-height: 200px;
                overflow-y: auto;
            }
        </style>
    </head>
    <body>
        <div class="dashboard-header">
            <div class="container">
                <h1>URL Phishing Analysis Dashboard</h1>
                <p class="mb-0">Automatic analysis of submitted URLs</p>
            </div>
        </div>
        
        <div class="container">
            <div class="refresh-container">
                <a href="admin_url_analyzer.jsp" class="btn btn-outline-secondary">Refresh Analysis</a>
            </div>
            
            <%
                // Variables to track summary statistics
                int totalUrls = 0;
                int safeUrls = 0;
                int phishingUrls = 0;
                int errorUrls = 0;
                
                // For debugging
                StringBuilder debugInfo = new StringBuilder();
                
                // Process will analyze URLs later, these variables are initialized here
                ArrayList<Map<String, Object>> urlAnalysisResults = new ArrayList<>();
                
                // Database connection information
                String dbURL = "jdbc:mysql://localhost:3306/p11";
                String dbUser = "root";
                String dbPass = "root";
                
                // Check if Python script exists - CORRECTED PATH
                String pythonScriptPath = application.getRealPath("/WEB-INF/python_scripts") + "/predict_url1.py";
                File pythonScript = new File(pythonScriptPath);
                boolean pythonScriptExists = pythonScript.exists();
                
                debugInfo.append("Python script path: " + pythonScript.getAbsolutePath() + "\n");
                debugInfo.append("Python script exists: " + pythonScriptExists + "\n");
                
                // Display any debug info for development
                if (!pythonScriptExists) {
            %>
                <div class="alert alert-danger">
                    <h4>Python Script Not Found</h4>
                    <p>The Python script 'predict_url1.py' was not found at the expected location.</p>
                    <p>Please check that the file exists and is accessible.</p>
                    <p>Expected path: <%= pythonScript.getAbsolutePath() %></p>
                </div>
            <% } %>
            
            <!-- Debug information for development -->
            <% if (request.getParameter("debug") != null) { %>
            <div class="card mb-4">
                <div class="card-header bg-warning">Debug Information</div>
                <div class="card-body p-0">
                    <div class="debug-info" id="debug-info"></div>
                </div>
            </div>
            <% } %>
            
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Analysis Summary</h5>
                        </div>
                        <div class="card-body">
                            <div id="summary-stats">
                                <div class="loading">
                                    <div class="spinner-border text-primary" role="status">
                                        <span class="visually-hidden">Loading...</span>
                                    </div>
                                    <p class="mt-2">Analyzing URLs...</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header bg-dark text-white">
                            <h5 class="mb-0">URL List</h5>
                        </div>
                        <div class="card-body" style="max-height: 500px; overflow-y: auto;">
                            <ul class="list-group" id="url-list">
                                <li class="list-group-item text-center">
                                    <div class="spinner-border spinner-border-sm text-primary" role="status">
                                        <span class="visually-hidden">Loading...</span>
                                    </div>
                                    Loading URLs...
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-8">
                    <h2 class="mb-4">Detailed Analysis</h2>
                    
                    <div id="detailed-analysis">
                        <div class="loading">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <p class="mt-2">Processing results...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <%
            // Create thread pool for concurrent analysis
            ExecutorService executor = Executors.newFixedThreadPool(5);
            
            Connection conn = null;
            Statement stmt = null;
            ResultSet rs = null;
            
            try {
                // Add JDBC driver info to debug
                debugInfo.append("JDBC Driver: com.mysql.jdbc.Driver\n");
                debugInfo.append("Database URL: " + dbURL + "\n");
                
                // Connect to database
                Class.forName("com.mysql.jdbc.Driver");
                conn = DriverManager.getConnection(dbURL, dbUser, dbPass);
                debugInfo.append("Database connection established successfully.\n");
                
                // Query to fetch all URLs
                String query = "SELECT id, name, url, descr, auth, dt FROM topics ORDER BY id DESC";
                stmt = conn.createStatement();
                rs = stmt.executeQuery(query);
                
                // List to store futures
                List<Future<Map<String, Object>>> futures = new ArrayList<>();
                
                // Process each URL and submit for analysis
                while(rs.next()) {
                    int id = rs.getInt("id");
                    String name = rs.getString("name");
                    String url = rs.getString("url");
                    String author = rs.getString("auth");
                    String dateAdded = rs.getString("dt");
                    
                    totalUrls++;
                    debugInfo.append("Processing URL #" + id + ": " + url + "\n");
                    
                    // Submit URL for analysis
                    Future<Map<String, Object>> future = executor.submit(() -> {
                        Map<String, Object> result = new HashMap<>();
                        result.put("id", id);
                        result.put("name", name);
                        result.put("url", url);
                        result.put("author", author);
                        result.put("dateAdded", dateAdded);
                        
                        try {
                            // Get Gemini analysis - add a try/catch specifically for this step
                            String geminiAnalysis = "";
                            try {
                                GeminiPhishingAnalyzer analyzer = new GeminiPhishingAnalyzer();
                                geminiAnalysis = analyzer.analyzeUrlRisk(url);
                            } catch (Exception e) {
                                geminiAnalysis = "Unable to analyze with Gemini: " + e.getMessage();
                                // Continue execution, don't fail the entire process for this URL
                            }
                            
                            // UPDATED: Use PythonBridge1 to call the predict_url1.py script
                            PythonBridge1 bridge = new PythonBridge1(application);
                            String processOutput = bridge.predictURL(url);
                            
                            debugInfo.append("Python output for " + url + ": " + processOutput + "\n");
                            
                            boolean isSafe = false;
                            double confidence = 0.0;
                            
                            // Process the prediction result
                            if (processOutput.startsWith("RESULT:")) {
                                String jsonStr = processOutput.substring(7).trim();
                                
                                // Process JSON string
                                try {
                                    JSONObject jsonResult = new JSONObject(jsonStr);
                                    isSafe = jsonResult.getBoolean("safe");
                                    confidence = jsonResult.getDouble("confidence");
                                } catch (Exception e) {
                                    // If direct parsing fails, try replacing single quotes with double quotes
                                    jsonStr = jsonStr.replace("'", "\"");
                                    JSONObject jsonResult = new JSONObject(jsonStr);
                                    isSafe = jsonResult.getBoolean("safe");
                                    confidence = jsonResult.getDouble("confidence");
                                }
                            } else {
                                // Log the error
                                result.put("error", "Failed to analyze URL: " + processOutput);
                                result.put("success", false);
                                return result;
                            }
                            
                            // Format the Gemini analysis for better readability
                            String formattedAnalysis = geminiAnalysis
                                .replace("**1. Domain Analysis:**", "<h3>1. Domain Analysis:</h3>")
                                .replace("**2. URL Structure:**", "<h3>2. URL Structure:</h3>")
                                .replace("**3. Risk Assessment:**", "<h3>3. Risk Assessment:</h3>")
                                .replace("**4. User Recommendations:**", "<h3>4. User Recommendations:</h3>")
                                .replace("**In Summary:**", "<h3>In Summary:</h3>")
                                .replace("* **", "<strong>")
                                .replace(":**", ":</strong>")
                                .replace("**", "")
                                .replace("* ", "<li>")
                                .replace("\n* ", "</li><li>")
                                .replaceAll("<li>([^<]+)</li>", "<li>$1</li>");
                            
                            // Add proper list tags
                            formattedAnalysis = formattedAnalysis
                                .replaceAll("<li>([\\s\\S]*?)((<h3>)|($))", "<ul><li>$1</li></ul>$2");
                            
                            result.put("isSafe", isSafe);
                            result.put("confidence", confidence);
                            result.put("formattedAnalysis", formattedAnalysis);
                            result.put("success", true);
                            
                        } catch (Exception e) {
                            result.put("error", "Error: " + e.getMessage());
                            result.put("success", false);
                            debugInfo.append("Error analyzing URL " + url + ": " + e.getMessage() + "\n");
                        }
                        
                        return result;
                    });
                    
                    futures.add(future);
                }
                
                // Wait for all analyses to complete
                for (Future<Map<String, Object>> future : futures) {
                    try {
                        Map<String, Object> result = future.get();
                        urlAnalysisResults.add(result);
                        
                        // Update stats
                        if (result.containsKey("success") && (Boolean)result.get("success")) {
                            if ((Boolean)result.get("isSafe")) {
                                safeUrls++;
                            } else {
                                phishingUrls++;
                            }
                        } else {
                            errorUrls++;
                        }
                    } catch (Exception e) {
                        Map<String, Object> errorResult = new HashMap<>();
                        errorResult.put("error", "Analysis failed: " + e.getMessage());
                        errorResult.put("success", false);
                        urlAnalysisResults.add(errorResult);
                        errorUrls++;
                        
                        debugInfo.append("Error processing a URL: " + e.getMessage() + "\n");
                    }
                }
                
                // Shutdown executor
                executor.shutdown();
                
                // Final debug info
                debugInfo.append("Analysis complete. Total: " + totalUrls + 
                                ", Safe: " + safeUrls + 
                                ", Phishing: " + phishingUrls + 
                                ", Errors: " + errorUrls + "\n");
                
            } catch (Exception e) {
                e.printStackTrace();
                debugInfo.append("SEVERE ERROR: " + e.getMessage() + "\n");
                for (StackTraceElement elem : e.getStackTrace()) {
                    debugInfo.append("  at " + elem.toString() + "\n");
                }
                %>
                <div class="alert alert-danger">
                    <h4>Application Error</h4>
                    <p><%= e.getMessage() %></p>
                    <% if (request.getParameter("debug") != null) { %>
                    <div class="debug-info">
                        <% for (StackTraceElement elem : e.getStackTrace()) { %>
                        <%= elem.toString() %><br>
                        <% } %>
                    </div>
                    <% } %>
                </div>
                <%
            } finally {
                // Close database resources
                if (rs != null) try { rs.close(); } catch (SQLException e) { debugInfo.append("Error closing ResultSet: " + e.getMessage() + "\n"); }
                if (stmt != null) try { stmt.close(); } catch (SQLException e) { debugInfo.append("Error closing Statement: " + e.getMessage() + "\n"); }
                if (conn != null) try { conn.close(); } catch (SQLException e) { debugInfo.append("Error closing Connection: " + e.getMessage() + "\n"); }
                if (executor != null && !executor.isShutdown()) {
                    executor.shutdownNow();
                }
            }
            
            // Store debug info in request attribute
            request.setAttribute("debugInfo", debugInfo.toString());
        %>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            // Function to safely escape special characters in strings for JavaScript
            function escapeJS(string) {
                return string
                    .replace(/\\/g, '\\\\')
                    .replace(/'/g, "\\'")
                    .replace(/"/g, '\\"')
                    .replace(/\n/g, '\\n')
                    .replace(/\r/g, '\\r')
                    .replace(/\t/g, '\\t');
            }
            
            // Update summary statistics
            document.getElementById('summary-stats').innerHTML = `
                <div class="row text-center">
                    <div class="col-md-4">
                        <h2><%= totalUrls %></h2>
                        <p>Total URLs</p>
                    </div>
                    <div class="col-md-4">
                        <h2 class="text-success"><%= safeUrls %></h2>
                        <p>Safe URLs</p>
                    </div>
                    <div class="col-md-4">
                        <h2 class="text-danger"><%= phishingUrls %></h2>
                        <p>Risky URLs</p>
                    </div>
                </div>
                <% if (errorUrls > 0) { %>
                <div class="alert alert-warning mt-2">
                    <%= errorUrls %> URLs failed to analyze properly.
                </div>
                <% } %>
                <div class="progress mt-3">
                    <div class="progress-bar bg-success" style="width: <%= totalUrls > 0 ? (safeUrls * 100 / totalUrls) : 0 %>%">
                        <%= totalUrls > 0 ? Math.round(safeUrls * 100 / totalUrls) : 0 %>%
                    </div>
                    <div class="progress-bar bg-danger" style="width: <%= totalUrls > 0 ? (phishingUrls * 100 / totalUrls) : 0 %>%">
                        <%= totalUrls > 0 ? Math.round(phishingUrls * 100 / totalUrls) : 0 %>%
                    </div>
                </div>
            `;
            
            // Update URL list
            let urlListHtml = '';
            
            <% 
            // Use StringBuilder for better string handling
            StringBuilder urlListBuilder = new StringBuilder();
            for (Map<String, Object> result : urlAnalysisResults) {
                if (result.containsKey("id")) { // Only add items with valid IDs
                    int id = (Integer)result.get("id");
                    String name = (String)result.get("name");
                    boolean hasSuccess = result.containsKey("success") && (Boolean)result.get("success");
                    boolean isSafe = hasSuccess && (Boolean)result.get("isSafe");
                    double confidence = hasSuccess ? (Double)result.get("confidence") : 0.0;
                    
                    urlListBuilder.append("urlListHtml += '<li class=\"list-group-item d-flex justify-content-between align-items-center\">");
                    urlListBuilder.append("<div><a href=\"#url-").append(id).append("\">").append(name).append("</a>");
                    if (hasSuccess) {
                        urlListBuilder.append("<span class=\"badge ").append(isSafe ? "bg-success" : "bg-danger").append(" ms-2\">");
                        urlListBuilder.append(isSafe ? "Safe" : "Risky").append("</span>");
                    } else {
                        urlListBuilder.append("<span class=\"badge bg-warning ms-2\">Error</span>");
                    }
                    urlListBuilder.append("</div>");
                    if (hasSuccess) {
                        urlListBuilder.append("<small class=\"text-muted\">").append(String.format("%.1f%%", confidence * 100)).append("</small>");
                    }
                    urlListBuilder.append("</li>';");
                }
            }
            %>
            
            <%= urlListBuilder.toString() %>
            
            document.getElementById('url-list').innerHTML = urlListHtml || '<li class="list-group-item">No URLs found</li>';
            
            // Update detailed analysis
            let analysisHtml = '';
            
            <% 
            // Use StringBuilder for better string handling of analysis section
            StringBuilder analysisBuilder = new StringBuilder();
            for (Map<String, Object> result : urlAnalysisResults) {
                if (result.containsKey("id")) { // Only process items with valid IDs
                    int id = (Integer)result.get("id");
                    String name = (String)result.get("name");
                    String url = (String)result.get("url");
                    String author = (String)result.get("author");
                    String dateAdded = (String)result.get("dateAdded");
                    boolean hasSuccess = result.containsKey("success") && (Boolean)result.get("success");
                    boolean isSafe = hasSuccess && (Boolean)result.get("isSafe");
                    String error = result.containsKey("error") ? (String)result.get("error") : "";
                    
                    analysisBuilder.append("analysisHtml += '<div class=\"card\" id=\"url-").append(id).append("\">");
                    analysisBuilder.append("<div class=\"card-header ");
                    if (hasSuccess) {
                        analysisBuilder.append(isSafe ? "bg-success" : "bg-danger");
                    } else {
                        analysisBuilder.append("bg-warning");
                    }
                    analysisBuilder.append(" text-white\"><h5 class=\"mb-0\">").append(name).append("</h5></div>");
                    analysisBuilder.append("<div class=\"card-body\">");
                    analysisBuilder.append("<div class=\"url-info\"><strong>URL:</strong> ");
                    analysisBuilder.append("<a href=\"").append(url).append("\" target=\"_blank\">").append(url).append("</a></div>");
                    
                    if (hasSuccess) {
                        analysisBuilder.append("<div class=\"url-info\"><strong>Status:</strong> ");
                        analysisBuilder.append("<span class=\"").append(isSafe ? "status-safe" : "status-phishing").append("\">");
                        analysisBuilder.append(isSafe ? "Safe" : "Potentially Phishing").append("</span></div>");
                        analysisBuilder.append("<div class=\"url-info\"><strong>Confidence:</strong> ");
                        analysisBuilder.append(String.format("%.1f%%", ((Double)result.get("confidence")) * 100)).append("</div>");
                    } else {
                        analysisBuilder.append("<div class=\"alert alert-warning\">").append(error).append("</div>");
                    }
                    
                    analysisBuilder.append("<div class=\"url-info\"><strong>Submitted by:</strong> ").append(author).append("</div>");
                    analysisBuilder.append("<div class=\"url-info\"><strong>Date Added:</strong> ").append(dateAdded).append("</div>");
                    
                    if (result.containsKey("formattedAnalysis")) {
                        String formattedAnalysis = (String)result.get("formattedAnalysis");
                        formattedAnalysis = formattedAnalysis.replace("\\", "\\\\").replace("'", "\\'").replace("\"", "\\\"").replace("\n", "");
                        
                        analysisBuilder.append("<div class=\"highlight mt-4\"><h4>Detailed Analysis</h4>");
                        analysisBuilder.append("<div class=\"analysis-content\">").append(formattedAnalysis).append("</div></div>");
                    }
                    
                    analysisBuilder.append("</div></div>';");
                }
            }
            %>
            
            <%= analysisBuilder.toString() %>
            
            document.getElementById('detailed-analysis').innerHTML = analysisHtml || '<div class="alert alert-info">No analysis results available</div>';
            
            // Update debug info if present
            <% if (request.getParameter("debug") != null) { %>
            let debugInfoText = '<%= debugInfo.toString().replace("\n", "\\n").replace("\"", "\\\"").replace("'", "\\'") %>';
            document.getElementById('debug-info').innerText = debugInfoText;
            <% } %>
            
            // Log to console for debugging
            console.log("Total URLs: <%= totalUrls %>");
            console.log("Safe URLs: <%= safeUrls %>");
            console.log("Phishing URLs: <%= phishingUrls %>");
            console.log("Error URLs: <%= errorUrls %>");
        </script>
    </body>
</html>