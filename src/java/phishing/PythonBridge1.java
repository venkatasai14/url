// PythonBridge.java
package phishing;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import javax.servlet.ServletContext;

public class PythonBridge1 {
    private ServletContext context;
    private static final String[] PYTHON_POSSIBLE_PATHS = {
        "C:\\Users\\Chaitanya Reddy\\AppData\\Local\\Programs\\Python\\Python39\\python.exe",
        "C:\\Users\\Chaitanya Reddy\\AppData\\Local\\Programs\\Python\\Python310\\python.exe",
        "C:\\Python39\\python.exe",
        "python.exe",
        "python"
    };
    
    public PythonBridge1(ServletContext context) {
        this.context = context;
    }
    
    private String findPythonPath() throws Exception {
        // First try to get Python path from system environment
        String pythonPath = System.getenv("PYTHON_PATH");
        if (pythonPath != null && new File(pythonPath).exists()) {
            return pythonPath;
        }
        
        // Try common Python installation paths
        for (String path : PYTHON_POSSIBLE_PATHS) {
            if (new File(path).exists()) {
                return path;
            }
            // Also try running python command to check if it's in PATH
            try {
                ProcessBuilder pb = new ProcessBuilder(path, "--version");
                Process p = pb.start();
                if (p.waitFor() == 0) {
                    return path;
                }
            } catch (Exception e) {
                // Continue to next path if this one fails
                continue;
            }
        }
        
        throw new Exception("Python executable not found. Please set PYTHON_PATH environment variable or install Python.");
    }
    
    public String predictURL(String url) throws Exception {
        // Get Python path
        String pythonPath = findPythonPath();
        System.out.println("Using Python path: " + pythonPath);
        
        // Get the real path to WEB-INF directory
        String webInfPath = context.getRealPath("/WEB-INF");
        String pythonScriptsPath = webInfPath + File.separator + "python_scripts";
        
        // Debug information
        System.out.println("WEB-INF Path: " + webInfPath);
        System.out.println("Python Scripts Path: " + pythonScriptsPath);
        
        // Verify directories and files exist
        File pythonDir = new File(pythonScriptsPath);
        if (!pythonDir.exists()) {
            throw new Exception("Python scripts directory not found at: " + pythonScriptsPath);
        }
        
        File scriptFile = new File(pythonScriptsPath + File.separator + "predict_url1.py");
        if (!scriptFile.exists()) {
            throw new Exception("predict_url.py not found at: " + scriptFile.getAbsolutePath());
        }
        
        // Build the command
        ProcessBuilder pb = new ProcessBuilder(
            pythonPath,
            scriptFile.getAbsolutePath(),
            url
        );
        
        // Set working directory
        pb.directory(pythonDir);
        
        // Redirect error stream to output stream
        pb.redirectErrorStream(true);
        
        // Debug: Print full command
        System.out.println("Full command: " + String.join(" ", pb.command()));
        
        // Start the process
        Process p = pb.start();
        
        // Read output
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
            System.out.println("Python output: " + line);
        }
        
        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new Exception("Python script failed with exit code: " + exitCode + "\nOutput: " + output.toString());
        }
        
        return output.toString().trim();
    }
}