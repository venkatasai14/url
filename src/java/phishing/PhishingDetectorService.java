package phishing;

import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.FastVector;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import javax.servlet.ServletContext;
import java.io.File;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.logging.Level;

public class PhishingDetectorService {
    private static final Logger LOGGER = Logger.getLogger(PhishingDetectorService.class.getName());
    private RandomForest model;
    private Instances header;
    private static final String DEFAULT_MODEL_PATH = "WEB-INF/models/phishing_detector_model.pkl";
    private ServletContext servletContext;
    
    // Known safe domains list
    private final List<String> knownSafeDomains = Arrays.asList(
        "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", 
        "twitter.com", "instagram.com", "linkedin.com", "github.com", "youtube.com"
    );
    
    public PhishingDetectorService(ServletContext servletContext) {
        this(servletContext, DEFAULT_MODEL_PATH);
    }
    
    public PhishingDetectorService(ServletContext servletContext, String modelPath) {
        this.servletContext = servletContext;
        loadModel(modelPath);
        initializeHeader();
    }
    
    private void loadModel(String modelPath) {
        try {
            // Try multiple ways to load the model
            InputStream modelStream = null;
            
            // First try: ServletContext resource
            if (servletContext != null) {
                modelStream = servletContext.getResourceAsStream("/" + modelPath);
            }
            
            // Second try: Classpath resource
            if (modelStream == null) {
                modelStream = getClass().getClassLoader().getResourceAsStream(modelPath);
            }
            
            // Third try: Direct file path
            if (modelStream == null && servletContext != null) {
                String realPath = servletContext.getRealPath("/" + modelPath);
                if (realPath != null) {
                    File modelFile = new File(realPath);
                    if (modelFile.exists()) {
                        model = (RandomForest) SerializationHelper.read(realPath);
                        return;
                    }
                }
            }
            
            // Load from stream if found
            if (modelStream != null) {
                model = (RandomForest) SerializationHelper.read(modelStream);
            } else {
                throw new RuntimeException("Could not locate model file at: " + modelPath);
            }
            
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error loading model from " + modelPath, e);
            throw new RuntimeException("Error loading model from " + modelPath + ": " + e.getMessage(), e);
        }
    }
    
    private void initializeHeader() {
        try {
            // Create header for Weka instances
            FastVector attributes = new FastVector();
            for (int i = 0; i < 30; i++) {
                attributes.addElement(new Attribute("feature" + i));
            }
            
            // Add class attribute
            FastVector classValues = new FastVector();
            classValues.addElement("phishing");
            classValues.addElement("legitimate");
            attributes.addElement(new Attribute("class", classValues));
            
            // Create header without instances
            header = new Instances("PhishingData", attributes, 0);
            header.setClassIndex(header.numAttributes() - 1);
            
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error initializing header", e);
            throw new RuntimeException("Error initializing header: " + e.getMessage(), e);
        }
    }
    
    public PredictionResult predict(String url) {
        try {
            if (url == null || url.trim().isEmpty()) {
                return new PredictionResult(false, 0.0, "Invalid URL: URL cannot be empty");
            }
            
            // Validate URL format
            try {
                new URI(url);
            } catch (Exception e) {
                return new PredictionResult(false, 0.0, "Invalid URL format");
            }
            
            // Extract domain for known safe domain check
            String domain = extractDomain(url);
            if (domain == null) {
                return new PredictionResult(false, 0.0, "Could not extract domain from URL");
            }
            
            // Check known safe domains
            for (String safeDomain : knownSafeDomains) {
                if (domain.endsWith(safeDomain)) {
                    return new PredictionResult(true, 0.95, "Known safe domain");
                }
            }
            
            // Extract features
            FeatureExtraction extractor = new FeatureExtraction(url);
            
            // Handle inaccessible URLs
            if (!extractor.isAccessible()) {
                return new PredictionResult(
                    false,
                    0.0,
                    "Error analyzing URL: " + extractor.getErrorMessage()
                );
            }
            
            List<Integer> features = extractor.getFeaturesList();
            
            // Validate feature list
            if (features.size() != 30) {
                LOGGER.warning("Invalid feature count: " + features.size());
                return new PredictionResult(false, 0.0, "Error analyzing URL features");
            }
            
            // Create instance
            Instance instance = new Instance(header.numAttributes());
            instance.setDataset(header);
            
            // Set feature values
            for (int i = 0; i < features.size(); i++) {
                instance.setValue(i, features.get(i));
            }
            
            // Make prediction
            double[] probabilities = model.distributionForInstance(instance);
            double phishingProb = probabilities[0]; // Probability of being phishing
            
            // Get critical features
            boolean isHttps = (features.get(7) == 1);  // Assuming Https is at index 7
            boolean hasIp = (features.get(0) == -1);
            boolean suspiciousDomain = (features.get(5) == -1 || features.get(6) == -1);
            
            // Default prediction based on probability
            boolean isPredictedPhishing = phishingProb > 0.5;
            
            // Apply special rules for HTTPS
            if (isHttps) {
                // For HTTPS URLs, require stronger evidence to mark as phishing
                if (isPredictedPhishing && phishingProb < 0.65) {
                    // Check if other strong indicators are present
                    int suspiciousFactors = 0;
                    if (hasIp) suspiciousFactors++;
                    if (features.get(1) == -1) suspiciousFactors++; // URL length
                    if (suspiciousDomain) suspiciousFactors++;
                    if (features.get(12) == -1) suspiciousFactors++; // RequestURL
                    if (features.get(13) == -1) suspiciousFactors++; // AnchorURL
                    if (features.get(14) == -1) suspiciousFactors++; // LinksInScriptTags
                    if (features.get(17) == -1) suspiciousFactors++; // AbnormalURL
                    
                    // If fewer than 2 suspicious factors, consider it safe
                    if (suspiciousFactors < 2) {
                        isPredictedPhishing = false;
                    }
                }
            } else {
                // For HTTP URLs, be slightly more strict
                if (!isPredictedPhishing && phishingProb > 0.4) {
                    // Check for suspicious factors
                    int suspiciousFactors = 0;
                    if (hasIp) suspiciousFactors++;
                    if (features.get(1) == -1) suspiciousFactors++; // URL length
                    if (suspiciousDomain) suspiciousFactors++;
                    if (features.get(12) == -1) suspiciousFactors++; // RequestURL
                    if (features.get(13) == -1) suspiciousFactors++; // AnchorURL
                    
                    // If multiple suspicious factors, mark as phishing
                    if (suspiciousFactors >= 2) {
                        isPredictedPhishing = true;
                    }
                }
            }
            
            // Calculate confidence
            double confidence = isPredictedPhishing ? phishingProb : (1 - phishingProb);
            
            // Determine message based on prediction
            String message = isPredictedPhishing ? 
                "This URL has been detected as a phishing website" :
                "This URL appears to be legitimate";
            
            return new PredictionResult(!isPredictedPhishing, confidence, message);
            
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error predicting URL: " + url, e);
            return new PredictionResult(
                false,
                0.0,
                "Error analyzing URL: " + e.getMessage()
            );
        }
    }
    
    private String extractDomain(String url) {
        try {
            String domain = new URI(url).getHost();
            if (domain == null) {
                return null;
            }
            return domain.startsWith("www.") ? domain.substring(4) : domain;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error extracting domain from URL: " + url, e);
            return null;
        }
    }
    
    // Result class to hold prediction information
    public static class PredictionResult {
        private boolean safe;
        private double confidence;
        private String message;
        
        public PredictionResult(boolean safe, double confidence, String message) {
            this.safe = safe;
            this.confidence = confidence;
            this.message = message;
        }
        
        public boolean isSafe() {
            return safe;
        }
        
        public double getConfidence() {
            return confidence;
        }
        
        public String getMessage() {
            return message;
        }
        
        public String getConfidencePercentage() {
            return String.format("%.1f%%", confidence * 100);
        }
    }
}