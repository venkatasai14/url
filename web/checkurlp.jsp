<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ page import="org.json.JSONObject" %>
<%@ page import="phishing.GeminiPhishingAnalyzer" %>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>URL Phishing Detector</title>
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
        </style>
    </head>
    <body>
        <div class="container mt-5">
            <h1 class="mb-4">URL Phishing Detector</h1>
            
            <form action="checkURL" method="post" class="mb-4">
                <div class="mb-3">
                    <label for="url" class="form-label">Enter URL to check:</label>
                    <input type="url" class="form-control" id="url" name="url" 
                           value="${param.url}" required>
                </div>
                <button type="submit" class="btn btn-primary">Check URL</button>
            </form>
            
            <% 
                // Display any error messages
                if (request.getAttribute("error") != null && 
                    !request.getAttribute("error").toString().isEmpty()) {
            %>
                    <div class="alert alert-danger">
                        <%= request.getAttribute("error") %>
                    </div>
            <%  } %>
            
            <% 
                // Process the result from the Python script, if available.
                if (request.getAttribute("result") != null && 
                    !request.getAttribute("result").toString().isEmpty()) { 
                    
                    String result = request.getAttribute("result").toString().trim();
                    
                    try {
                        if (result.startsWith("RESULT:")) {
                            // Remove "RESULT:" prefix
                            result = result.substring(7).trim();
                            
                            // Convert string to JSON object
                            JSONObject jsonObject = new JSONObject(result);
                            boolean isSafe = jsonObject.getBoolean("safe");
                            double confidence = jsonObject.getDouble("confidence");
            %>
                            <div class="card mb-4">
                                <div class="card-body">
                                    <h5 class="card-title">Analysis Result</h5>
                                    <p class="card-text">
                                        <strong>URL:</strong> ${param.url}<br>
                                        <strong>Status:</strong> 
                                        <span class="badge <%= isSafe ? "bg-success" : "bg-danger" %>">
                                            <%= isSafe ? "Safe" : "Potentially Phishing" %>
                                        </span><br>
                                        <strong>Confidence:</strong> <%= String.format("%.1f%%", confidence * 100) %>
                                    </p>
                                </div>
                            </div>
            <%  
                        } else {
                            throw new Exception("Invalid result format");
                        }
                    } catch (Exception e) {
                        System.out.println("Error parsing result: " + result);
                        e.printStackTrace();
                        request.setAttribute("error", "Error parsing result: " + e.getMessage());
            %>
                        <div class="alert alert-danger">
                            <%= request.getAttribute("error") %>
                        </div>
            <%      }
                }
            %>
            
            <% 
                // If a URL is provided, call GeminiPhishingAnalyzer to get additional insights.
                String inputUrl = request.getParameter("url");
                if (inputUrl != null && !inputUrl.trim().isEmpty()) {
                    GeminiPhishingAnalyzer analyzer = new GeminiPhishingAnalyzer();
                    String geminiAnalysis = analyzer.analyzeUrlRisk(inputUrl);
                    
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
            %>
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">Gemini Insights</h5>
                        </div>
                        <div class="card-body">
                            <p class="mb-3">
                                <strong>URL:</strong> <%= inputUrl %>
                            </p>
                            <div class="highlight">
                                <div class="analysis-content">
                                    <%= formattedAnalysis %>
                                </div>
                            </div>
                        </div>
                    </div>
            <% } %>
            
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
</html>