package phishing;

import javax.servlet.ServletContext;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

public class PythonScriptLoader {
    public static String extractPythonScript(ServletContext context) throws Exception {
        String tempDir = System.getProperty("java.io.tmpdir");
        File pythonScript = new File(tempDir, "predict.py");
        
        // Copy Python script from WEB-INF to temp directory
        try (InputStream in = context.getResourceAsStream("/WEB-INF/python/predict.py")) {
            Files.copy(in, pythonScript.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
        
        return pythonScript.getAbsolutePath();
    }
}