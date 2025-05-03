package phishing;

import phishing.PythonBridge;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name = "CheckURLServlet", urlPatterns = {"/checkURL"})
public class CheckURLServlet extends HttpServlet {
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        
        String url = request.getParameter("url");
        String result = "";
        String error = "";
        
        try {
            if (url != null && !url.trim().isEmpty()) {
                PythonBridge bridge = new PythonBridge(getServletContext());
                result = bridge.predictURL(url);
            }
        } catch (Exception e) {
            error = "Error processing URL: " + e.getMessage();
            e.printStackTrace(); // This will print to Tomcat's logs
        }
        
        request.setAttribute("result", result);
        request.setAttribute("error", error);
        request.setAttribute("url", url);
        request.getRequestDispatcher("checkurlp.jsp").forward(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }
}