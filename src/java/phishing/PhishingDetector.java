package phishing;

import javax.servlet.ServletContext;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import java.util.HashMap; // Add this import
import java.util.Map; // Add this import
public class PhishingDetector {
    private final ServletContext context;
    private String pythonScriptPath;
    private String modelPath;
    private String vectorizerPath;
    
    public PhishingDetector(ServletContext context) {
        this.context = context;
        initializePaths();
    }
    
    private void initializePaths() {
        try {
            // Get real path for model files
            String webInfPath = context.getRealPath("/WEB-INF");
            this.modelPath = webInfPath + "/models/svm_modelfinal.joblib";
            this.vectorizerPath = webInfPath + "/models/count_vectorizerfinal.joblib";
            
            // Extract Python script to temporary location
            this.pythonScriptPath = PythonScriptLoader.extractPythonScript(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Modify PhishingDetector.java to add more detailed logging
public String detectPhishing(String url) {
    String pythonPath = "C:\\Users\\Chaitanya Reddy\\AppData\\Local\\Programs\\Python\\Python311\\python.exe";
    File pythonExe = new File(pythonPath);
    
    if (!pythonExe.exists()) {
        System.err.println("Python executable not found at: " + pythonPath);
        return "Error: Python executable not found";
    }
    
    try {
        ProcessBuilder pb = new ProcessBuilder(
            pythonPath,
            pythonScriptPath,
            url,
            modelPath,
            vectorizerPath
        );
        
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        BufferedReader errorReader = new BufferedReader(
            new InputStreamReader(process.getErrorStream()));
        
        // Log any errors
        String errorLine;
        while ((errorLine = errorReader.readLine()) != null) {
            System.err.println("Python Error: " + errorLine);
        }
        
        String result = reader.readLine();
        process.waitFor();
        
        return result != null ? result : "No classification";
    } catch (Exception e) {
        e.printStackTrace();
        return "Error: " + e.getMessage();
    }
}
}