<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@page import="phishing.PhishingDetectorService"%>
<%@page import="phishing.PhishingDetectorService.PredictionResult"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Phishing URL Detector</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f5f5f5;
                padding-top: 50px;
            }
            .container {
                max-width: 800px;
                background-color: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .result-safe {
                background-color: #d4edda;
                color: #155724;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
            }
            .result-unsafe {
                background-color: #f8d7da;
                color: #721c24;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
            }
            .form-control {
                height: 50px;
                font-size: 18px;
            }
            .btn-check {
                height: 50px;
                font-size: 18px;
            }
            .loading {
                display: none;
                text-align: center;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="text-center mb-4">Phishing URL Detector</h1>
            
            <form action="checkurl.jsp" method="post" class="mb-4" id="urlForm">
                <div class="input-group mb-3">
                    <input type="text" name="url" class="form-control" 
                           placeholder="Enter URL to check (e.g., https://example.com)" 
                           required value="${param.url != null ? param.url : ''}">
                    <button class="btn btn-primary btn-check" type="submit">Check URL</button>
                </div>
            </form>
            
            <div class="loading">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2">Analyzing URL...</p>
            </div>
            
            <%
                String url = request.getParameter("url");
                if (url != null && !url.isEmpty()) {
                    try {
                        PhishingDetectorService service = new PhishingDetectorService(application);
                        PredictionResult result = service.predict(url);
                        
                        if (result.isSafe()) {
            %>
                <div class="result-safe">
                    <h4><i class="bi bi-shield-check"></i> <%= result.getMessage() %></h4>
                    <p>We've analyzed this URL and it appears to be legitimate.</p>
                    <p><strong>Confidence:</strong> <%= result.getConfidencePercentage() %></p>
                </div>
            <%
                        } else {
            %>
                <div class="result-unsafe">
                    <h4><i class="bi bi-shield-exclamation"></i> <%= result.getMessage() %></h4>
                    <p>This URL has been identified as potentially dangerous. We recommend not visiting this site.</p>
                    <p><strong>Confidence:</strong> <%= result.getConfidencePercentage() %></p>
                </div>
            <%
                        }
                    } catch (Exception e) {
                        application.log("Error in phishing detection", e);
            %>
                <div class="alert alert-danger">
                    <h4><i class="bi bi-exclamation-triangle"></i> Error</h4>
                    <p>Unable to process URL at this time. Please try again later.</p>
                    <p><small class="text-muted">Error details: <%= e.getMessage() %></small></p>
                </div>
            <%
                    }
                }
            %>
            
            <div class="mt-5">
                <h3>How it works:</h3>
                <p>Our phishing detection system analyzes URLs using machine learning and considers multiple factors:</p>
                <ul>
                    <li>Domain and URL structure analysis</li>
                    <li>SSL certificate verification</li>
                    <li>Content examination for suspicious elements</li>
                    <li>Comparison against known phishing patterns</li>
                    <li>Analysis of external resources and links</li>
                    <li>Evaluation of website behavior and scripts</li>
                </ul>
                
                <div class="mt-4">
                    <h4>Safety Tips:</h4>
                    <div class="alert alert-info">
                        <ul class="mb-0">
                            <li>Always verify the URL in your browser's address bar</li>
                            <li>Look for HTTPS and valid certificates on sensitive websites</li>
                            <li>Be cautious of URLs received in unsolicited emails</li>
                            <li>Don't enter personal information on unfamiliar websites</li>
                            <li>Keep your browser and security software up to date</li>
                        </ul>
                    </div>
                </div>
                
                <div class="mt-4">
                    <h4>Limitations:</h4>
                    <div class="alert alert-warning">
                        <p><strong>Note:</strong> While our system is highly accurate, please exercise caution when visiting unfamiliar websites.</p>
                        <ul class="mb-0">
                            <li>Always verify the legitimacy of sensitive websites (banking, email, etc.) independently</li>
                            <li>The system may not detect newly created phishing sites</li>
                            <li>Some legitimate sites may be incorrectly flagged if they use unusual patterns</li>
                            <li>The analysis may take longer for complex websites</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <footer class="container text-center mt-4 mb-4">
            <p class="text-muted">
                Phishing URL Detector - A machine learning-based security tool
                <br>
                <small>For educational and informational purposes only</small>
            </p>
        </footer>
        
        <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
        <script>
            document.getElementById('urlForm').addEventListener('submit', function() {
                document.querySelector('.loading').style.display = 'block';
            });
            
            // Add URL validation
            document.querySelector('input[name="url"]').addEventListener('input', function(e) {
                let url = e.target.value.trim();
                let submitButton = document.querySelector('.btn-check');
                
                // Basic URL validation
                if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
                    url = 'https://' + url;
                    e.target.value = url;
                }
                
                try {
                    new URL(url);
                    submitButton.disabled = false;
                    e.target.classList.remove('is-invalid');
                } catch (err) {
                    if (url) {
                        submitButton.disabled = true;
                        e.target.classList.add('is-invalid');
                    }
                }
            });
            
            // Add tooltip for helpful information
            const urlInput = document.querySelector('input[name="url"]');
            urlInput.setAttribute('data-bs-toggle', 'tooltip');
            urlInput.setAttribute('data-bs-placement', 'bottom');
            urlInput.setAttribute('title', 'Enter a complete URL starting with http:// or https://');
            
            // Initialize tooltips
            var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        </script>
    </body>
</html>