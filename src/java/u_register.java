/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.sql.*;


import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

@WebServlet("/u_register")
@MultipartConfig(maxFileSize = 16177215)  
public class u_register extends HttpServlet {

    private String dbURL = "jdbc:mysql://localhost:3306/p11?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true";
    private String dbUser = "root";
    private String dbPass = "root";
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, ClassNotFoundException {
         response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        int ff=0,n = 0,n1 = 0;
        String userid = request.getParameter("userid");
        String pass = request.getParameter("pass");
        String email = request.getParameter("email");
        String mobile = request.getParameter("mobile");
        String address = request.getParameter("address");
        String dob = request.getParameter("dob");
        String gender = request.getParameter("gender");
        String pincode = request.getParameter("pincode");
        String location = request.getParameter("location");
         
        InputStream inputStream = null; // input stream of the upload file
         
        // obtains the upload file part in this multipart request
        Part filePart = request.getPart("pic");
        if (filePart != null) {
            // prints out some information for debugging
            System.out.println(filePart.getName());
            System.out.println(filePart.getSize());
            System.out.println(filePart.getContentType());
             
            // obtains input stream of the upload file
            inputStream = filePart.getInputStream();
        }
         
        Connection conn = null; // connection to the database
        String message = null;  // message will be sent back to client
         
        try {
            // connects to the database
            Class.forName("com.mysql.jdbc.Driver");
            conn = DriverManager.getConnection(dbURL, dbUser, dbPass);
 
            // constructs SQL statement
            
            String query1="select * from user  where name='"+userid+"' or email='"+email+"' or mobile='"+mobile+"' "; 
	    Statement st1=(Statement) conn.createStatement();
	    ResultSet rs1=st1.executeQuery(query1);
            
            if(!rs1.next()){
            String sql = "insert into user(name,pass,email,mobile,addr,dob,gender,pin,location,image,status) values(?,?,?,?,?,?,?,?,?,?,?)";
            PreparedStatement statement = conn.prepareStatement(sql);
            statement.setString(1, userid);
            statement.setString(2, pass);
            statement.setString(3, email);
            statement.setString(4, mobile);
            statement.setString(5, address);
            statement.setString(6, dob);
            statement.setString(7, gender);
            statement.setString(8, pincode);
            statement.setString(9, location);
            
             
            if (inputStream != null) {
                // fetches input stream of the upload file for the blob column
                statement.setBlob(10, inputStream);
            }
             statement.setString(11, "waiting");
 
            // sends the statement to the database server
            int row = statement.executeUpdate();
            if (row == 1) {
                
                String query5="select * from user "; 
					Statement st5=conn.createStatement();
					ResultSet rs5=st5.executeQuery(query5);
					while( rs5.next())
					{
					  n++;
					}
					String query15="select * from blocked_user "; 
					Statement st15=conn.createStatement();
					ResultSet rs15=st15.executeQuery(query15);
					while( rs15.next())
					{
					  n1++;
					}
					
					int n2=n-n1;//Unblocked users
					
					
						
				    String strQuery21 = "update bnb_users set number="+n1+ " where user='Blocked Users' ";
				    conn.createStatement().executeUpdate(strQuery21);
					
					String strQuery212 = "update bnb_users set number="+n2+ " where user='UnBlocked Users' ";
				    conn.createStatement().executeUpdate(strQuery212);
                
                response.sendRedirect("u_register.html?Registration_done_success");
                
            }
            }
            else
            {
               response.sendRedirect("index.html?Registration_failed");
            }
        } catch (SQLException ex) {
            
            ex.printStackTrace();
        } finally {
            if (conn != null) {
                // closes the database connection
                try {
                    conn.close();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            processRequest(request, response);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(u_register.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            processRequest(request, response);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(u_register.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
