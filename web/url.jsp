<%@ page import="phishing.PhishingDetector" %>
<%@ page import="phishing.GeminiPhishingAnalyzer" %>
<%@ page contentType="text/html" pageEncoding="UTF-8" %>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Phishing URL Detection</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
</head>
<body class="antialiased bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <div class="max-w-4xl mx-auto bg-white shadow-lg rounded-lg overflow-hidden">
            <div class="px-6 py-4 bg-blue-600 text-white">
                <h1 class="text-2xl font-bold">Advanced URL Phishing Detection</h1>
            </div>
            
            <div class="p-6">
                <form method="post" action="" class="space-y-4">
                    <div>
                        <label for="url" class="block text-sm font-medium text-gray-700">Enter URL to Check</label>
                        <div class="mt-1 flex rounded-md shadow-sm">
                            <input 
                                type="url" 
                                name="url" 
                                id="url" 
                                required 
                                placeholder="https://example.com" 
                                class="flex-1 block w-full rounded-md border-gray-300 focus:ring-blue-500 focus:border-blue-500 sm:text-sm p-2"
                            >
                            <button 
                                type="submit" 
                                class="ml-3 inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                            >
                                Analyze URL
                            </button>
                        </div>
                    </div>
                </form>
                <%
                    String url = request.getParameter("url");
                    if (url != null && !url.trim().isEmpty()) {
                        PhishingDetector detector = new PhishingDetector(application);
                        GeminiPhishingAnalyzer geminiAnalyzer = new GeminiPhishingAnalyzer();
                        
                        String mlResult = detector.detectPhishing(url);
                        String geminiAnalysis = geminiAnalyzer.analyzeUrlRisk(url);
                %>
                    <div class="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                        <!-- ML Model Result -->
                        <div class="bg-gray-100 border-l-4 <%= mlResult.contains("Malicious") ? "border-red-500" : "border-green-500" %> p-4">
                            <h3 class="text-sm font-medium <%= mlResult.contains("Malicious") ? "text-red-800" : "text-green-800" %>">
                                Machine Learning Analysis
                            </h3>
                            <div class="mt-2 text-sm">
                                <p><strong>URL:</strong> <%= url %></p>
                                <p class="mt-1">
                                    <strong>Classification:</strong> 
                                    <span class="<%= mlResult.contains("Malicious") ? "text-red-700" : "text-green-700" %>">
                                        <%= mlResult %>
                                    </span>
                                </p>
                            </div>
                        </div>
                        
                        <!-- Gemini AI Analysis -->
                        <div class="bg-gray-100 border-l-4 <%= mlResult.contains("Malicious") ? "border-red-500" : "border-green-500" %> p-4">
                            <h3 class="text-sm font-medium <%= mlResult.contains("Malicious") ? "text-red-800" : "text-green-800" %>">
                                AI-Powered Risk Analysis
                            </h3>
                            <div class="mt-2 text-sm">
                                <p><strong>Gemini Pro Insights:</strong></p>
                                <p class="mt-1 text-gray-700"><%= geminiAnalysis %></p>
                            </div>
                        </div>
                    </div>
                <%
                    }
                %>
            </div>
        </div>
    </div>
</body>
</html>