package phishing;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStreamWriter;
import javax.servlet.ServletContext;
import org.json.JSONObject;

public class GeminiPhishingAnalyzer {
    private static final String GEMINI_API_KEY = "Replace with actual API key"; // Replace with actual API key
    private static final String GEMINI_API_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + GEMINI_API_KEY;

    public String analyzeUrlRisk(String inputUrl) {
        try {
            // Construct enhanced security analysis prompt
            String prompt = "Security Analysis for URL: " + inputUrl + "\n\n" +
                            "Please analyze:\n" +
                            "1. Domain Analysis:\n" +
                            "   - Brand impersonation check\n" +
                            "   - Domain age and reputation indicators\n" +
                            "   - Common phishing patterns\n\n" +
                            "2. URL Structure:\n" +
                            "   - Suspicious parameters or encoding\n" +
                            "   - Hidden redirects\n" +
                            "   - Malformed components\n\n" +
                            "3. Risk Assessment:\n" +
                            "   - Likelihood of phishing\n" +
                            "   - Potential attack vectors\n" +
                            "   - Similar known threats\n\n" +
                            "4. User Recommendations:\n" +
                            "   - Specific security concerns\n" +
                            "   - Safe browsing advice\n" +
                            "   - Alternative legitimate URLs if this appears suspicious\n\n" +
                            "Provide a clear, structured analysis focusing on concrete security indicators.";
            
            // Prepare JSON payload
            JSONObject requestBody = new JSONObject();
            JSONObject content = new JSONObject();
            content.put("role", "user");
            content.put("parts", new JSONObject().put("text", prompt));
            requestBody.put("contents", new JSONObject[]{content});
            
            // Send request to Gemini Pro
            URL url = new URL(GEMINI_API_ENDPOINT);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);
            
            // Write request body
            try (OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream())) {
                writer.write(requestBody.toString());
            }
            
            // Read response
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                
                // Parse response and extract Gemini's analysis
                JSONObject jsonResponse = new JSONObject(response.toString());
                String geminiAnalysis = jsonResponse.getJSONArray("candidates")
                                                    .getJSONObject(0)
                                                    .getJSONObject("content")
                                                    .getJSONArray("parts")
                                                    .getJSONObject(0)
                                                    .getString("text");
                return geminiAnalysis;
            } else {
                return "Error analyzing URL. Response Code: " + responseCode;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "API Error: " + e.getMessage();
        }
    }
}
