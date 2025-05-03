package phishing;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

class FeatureExtraction {
    private String url;
    private String domain;
    private URI uri;
    private Document doc;
    private boolean isAccessible = true;
    private String errorMessage = null;
    
    public FeatureExtraction(String url) {
        this.url = url;
        try {
            this.uri = new URI(url);
            this.domain = uri.getHost();
            if (domain != null && domain.startsWith("www.")) {
                domain = domain.substring(4);
            }
            
            // More robust connection handling
            try {
                this.doc = Jsoup.connect(url)
                    .timeout(5000)
                    .followRedirects(true)
                    .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .get();
            } catch (Exception e) {
                this.isAccessible = false;
                this.errorMessage = "Could not access URL: " + e.getMessage();
            }
            
        } catch (Exception e) {
            this.isAccessible = false;
            this.errorMessage = "Invalid URL format: " + e.getMessage();
        }
    }
    
    public boolean isAccessible() {
        return isAccessible;
    }
    
    public String getErrorMessage() {
        return errorMessage;
    }
    
    public List<Integer> getFeaturesList() {
        List<Integer> features = new ArrayList<>();
        
        features.add(usingIp());
        features.add(longUrl());
        features.add(shortUrl());
        features.add(symbol());
        features.add(redirecting());
        features.add(prefixSuffix());
        features.add(subDomains());
        features.add(https());
        features.add(domainRegLen());
        features.add(favicon());
        features.add(nonStdPort());
        features.add(httpsDomainUrl());
        features.add(requestUrl());
        features.add(anchorUrl());
        features.add(linksInScriptTags());
        features.add(serverFormHandler());
        features.add(infoEmail());
        features.add(abnormalUrl());
        features.add(websiteForwarding());
        features.add(statusBarCust());
        features.add(disableRightClick());
        features.add(usingPopupWindow());
        features.add(iframeRedirection());
        features.add(ageOfDomain());
        features.add(dnsRecording());
        features.add(websiteTraffic());
        features.add(pageRank());
        features.add(googleIndex());
        features.add(linksPointingToPage());
        features.add(statsReport());
        
        return features;
    }
    
    private int usingIp() {
        try {
            InetAddress address = InetAddress.getByName(domain);
            String ip = address.getHostAddress();
            return domain.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") ? -1 : 1;
        } catch (UnknownHostException e) {
            return 1;
        }
    }
    
    private int longUrl() {
        if (url.length() < 54) return 1;
        if (url.length() >= 54 && url.length() <= 75) return 0;
        return -1;
    }
    
    private int shortUrl() {
        String[] shorteners = {
            "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl",
            "tr.im", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu",
            "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to", "BudURL.com", "ping.fm",
            "post.ly", "Just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com",
            "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "t.co",
            "lnkd.in", "db.tt", "qr.ae", "adf.ly", "goo.gl", "bitly.com", "cur.lv", "tinyurl.com",
            "ow.ly", "bit.ly", "ity.im", "q.gs", "is.gd", "po.st", "bc.vc", "twitthis.com", "u.to",
            "j.mp", "buzurl.com", "cutt.us", "u.bb", "yourls.org", "x.co", "prettylinkpro.com",
            "scrnch.me", "filoops.info", "vzturl.com", "qr.net", "1url.com", "tweez.me", "v.gd",
            "tr.im", "link.zip.net"
        };
        
        for (String shortener : shorteners) {
            if (domain.contains(shortener)) {
                return -1;
            }
        }
        return 1;
    }
    
    private int symbol() {
        return url.contains("@") ? -1 : 1;
    }
    
    private int redirecting() {
        return url.lastIndexOf("//") > 7 ? -1 : 1;
    }
    
    private int prefixSuffix() {
        return domain.contains("-") ? -1 : 1;
    }
    
    private int subDomains() {
        int dotCount = 0;
        for (char c : domain.toCharArray()) {
            if (c == '.') dotCount++;
        }
        
        if (dotCount == 1) return 1;
        if (dotCount == 2) return 0;
        return -1;
    }
    
    private int https() {
        try {
            String protocol = uri.getScheme();
            if ("https".equals(protocol)) {
                int suspiciousCount = 0;
                if (subDomains() == -1) suspiciousCount++;
                if (prefixSuffix() == -1) suspiciousCount++;
                if (favicon() == -1) suspiciousCount++;
                if (requestUrl() == -1) suspiciousCount++;
                
                if (suspiciousCount >= 2) {
                    return 0;
                }
                return 1;
            }
            return -1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int domainRegLen() {
        return 0;
    }
    
    private int favicon() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            Elements links = doc.select("head link[href]");
            for (Element link : links) {
                String href = link.attr("href");
                if (href.contains("favicon") || href.contains(".ico")) {
                    if (href.startsWith("http") && !href.contains(domain)) {
                        return -1;
                    }
                    return 1;
                }
            }
            return -1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int nonStdPort() {
        String[] parts = domain.split(":");
        return parts.length > 1 ? -1 : 1;
    }
    private int httpsDomainUrl() {
        return domain.contains("https") ? -1 : 1;
    }
    
    private int requestUrl() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            Elements imgs = doc.select("img[src]");
            Elements audio = doc.select("audio[src]");
            Elements embeds = doc.select("embed[src]");
            Elements iframes = doc.select("iframe[src]");
            
            int totalElements = imgs.size() + audio.size() + embeds.size() + iframes.size();
            if (totalElements == 0) return 0;
            
            int externalCount = 0;
            
            for (Element e : imgs) externalCount += isExternalSource(e.attr("src")) ? 1 : 0;
            for (Element e : audio) externalCount += isExternalSource(e.attr("src")) ? 1 : 0;
            for (Element e : embeds) externalCount += isExternalSource(e.attr("src")) ? 1 : 0;
            for (Element e : iframes) externalCount += isExternalSource(e.attr("src")) ? 1 : 0;
            
            double percentage = (externalCount * 100.0) / totalElements;
            
            if (percentage < 22.0) return 1;
            if (percentage >= 22.0 && percentage < 61.0) return 0;
            return -1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private boolean isExternalSource(String src) {
        return !(src.startsWith(url) || src.startsWith("/") || src.startsWith("./") || 
                 src.startsWith("../") || (!src.contains("://") && !src.startsWith("//")));
    }
    
    private int anchorUrl() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            Elements anchors = doc.select("a[href]");
            if (anchors.isEmpty()) return 0;
            
            int suspiciousCount = 0;
            for (Element a : anchors) {
                String href = a.attr("href");
                if (href.startsWith("#") || 
                    href.toLowerCase().startsWith("javascript") || 
                    href.toLowerCase().startsWith("mailto") || 
                    !(href.contains(domain) || href.startsWith("/"))) {
                    suspiciousCount++;
                }
            }
            
            double percentage = (suspiciousCount * 100.0) / anchors.size();
            
            if (percentage < 31.0) return 1;
            if (percentage >= 31.0 && percentage < 67.0) return 0;
            return -1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int linksInScriptTags() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            Elements links = doc.select("link[href]");
            Elements scripts = doc.select("script[src]");
            
            int totalElements = links.size() + scripts.size();
            if (totalElements == 0) return 0;
            
            int externalCount = 0;
            
            for (Element e : links) externalCount += isExternalSource(e.attr("href")) ? 1 : 0;
            for (Element e : scripts) externalCount += isExternalSource(e.attr("src")) ? 1 : 0;
            
            double percentage = (externalCount * 100.0) / totalElements;
            
            if (percentage < 17.0) return 1;
            if (percentage >= 17.0 && percentage < 81.0) return 0;
            return -1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int serverFormHandler() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            Elements forms = doc.select("form[action]");
            if (forms.isEmpty()) return 1;
            
            for (Element form : forms) {
                String action = form.attr("action");
                if (action.isEmpty() || action.equals("about:blank")) {
                    return -1;
                }
                if (!action.contains(domain) && !action.startsWith("/")) {
                    return 0;
                }
            }
            return 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int infoEmail() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            Pattern pattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
            Matcher matcher = pattern.matcher(doc.text());
            return matcher.find() ? -1 : 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int abnormalUrl() {
        try {
            String host = uri.getHost().toLowerCase();
            if (host == null || !host.equals(domain.toLowerCase())) {
                return -1;
            }
            return 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int websiteForwarding() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            Elements metas = doc.select("meta[http-equiv=refresh]");
            return !metas.isEmpty() ? -1 : 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int statusBarCust() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            Pattern pattern = Pattern.compile("<script>.+onmouseover.+</script>");
            Matcher matcher = pattern.matcher(doc.html());
            return matcher.find() ? -1 : 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int disableRightClick() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            return doc.html().contains("event.button == 2") || 
                   doc.html().contains("event.button===2") ? -1 : 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int usingPopupWindow() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            return doc.html().contains("alert(") || 
                   doc.html().contains("confirm(") ? -1 : 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int iframeRedirection() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            return !doc.select("iframe").isEmpty() ? -1 : 1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    // Following features return neutral scores as they require external services
    private int ageOfDomain() {
        return 0;
    }
    
    private int dnsRecording() {
        return 0;
    }
    
    private int websiteTraffic() {
        return 0;
    }
    
    private int pageRank() {
        return 0;
    }
    
    private int googleIndex() {
        return 0;
    }
    
    private int linksPointingToPage() {
        try {
            if (!isAccessible || doc == null) {
                return 0;
            }
            
            int linkCount = doc.select("a[href]").size();
            
            if (linkCount == 0) return 1;
            if (linkCount <= 2) return 0;
            return -1;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int statsReport() {
        String[] suspiciousDomains = {
            "at.ua", "usa.cc", "baltazarpresentes.com.br", "pe.hu", "esy.es", "hol.es", "sweddy.com",
            "myjino.ru", "96.lt", "ow.ly"
        };
        
        for (String suspicious : suspiciousDomains) {
            if (url.contains(suspicious)) {
                return -1;
            }
        }
        
        try {
            InetAddress address = InetAddress.getByName(domain);
            String ip = address.getHostAddress();
            
            String[] suspiciousIps = {
                "146.112.61.108", "213.174.157.151", "121.50.168.88", "192.185.217.116",
                "198.54.117.200", "192.185.217.108", "69.50.209.78", "46.242.145.98"
            };
            
            for (String suspiciousIp : suspiciousIps) {
                if (ip.equals(suspiciousIp)) {
                    return -1;
                }
            }
            
            return 1;
        } catch (UnknownHostException e) {
            return 0;
        }
    }
}