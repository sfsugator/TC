/*******************************************************************************************************
 Author: Alf Muller
 File: CSVImportCodes.java
 Class: CSC675 Databases
 Comments: This program takes a csv file as an input and reads the file line by line with a
 buffered reader. A JDBC driver is used to connect to our postgresql database on our server
 and INSERT the rows into the "airportCodes" table using a PreparedStatement. This table holds info
 for airport codes around the world. Regex is used on the rows to split by colon. Strings that are numeric
 are converted to ints. A change was made to the input file: there were almost 600 instances of headers
 in the file that were removed as they were being added as rows.
 ******************************************************************************************************/




import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.FileReader;
import java.sql.*;
import org.postgresql.*;

public class CSVImportCodes {
    public static void main(String[] args) {
        
        Connection con = null;
        PreparedStatement pst = null;
        //ResultSet rs = null;//Not used in this query
        FileReader fr = null;
        
        //Connection variables
        String JDBCdriver = "org.postgresql.Driver";
        String url = "jdbc:postgresql://localhost:5432";
        String user = "amuller";
        String password = "tbontb73";
        
        try {
            Class<?> driver = Class.forName(JDBCdriver);//Initialize the driver
            con = DriverManager.getConnection(url, user, password);//Make the connection
            
            
            BufferedReader input = new BufferedReader(new FileReader("airport-codes.csv"));//Input file
            int x = 0;//Variable to hold ints
            
            String line = null;
            String stm = "INSERT INTO airportCodes VALUES(?,?,?,?,?,?)";//Insert string
            while (( line = input.readLine()) != null) {//While there are rows in file
                String[] fields = parseCSVLine(line);//Send to parser and store
                for ( int i = 0; i < fields.length; i+=6 ) {//Prepare statements and execute
                    pst = con.prepareStatement(stm);
                    pst.setString(1, fields[i]);
                    i++;
                    pst.setString(2, fields[i]);
                    i++;
                    pst.setString(3, fields[i]);
                    i++;
                    pst.setString(4, fields[i]);
                    i++;
                    pst.setString(5, fields[i]);
                    i++;
                    x = Integer.parseInt(fields[i]);
                    pst.setInt(6, x);
                    i++;
                    pst.executeUpdate();//Execute the statement
                    //print first field of each row to watch the database load, can be commented out
                    System.out.println("Done entering line: " + fields[i-6] + "\n");
                }
            }
            //Close Connections
            input.close();
            pst.close();
            con.close();
            
        }
        catch(Exception ex) {//Catch try
            System.out.println("Error: " + ex.getMessage());
        }
    }
    
    public static String[] parseCSVLine(String line) {
        //Regex splits by comma; commas between quotes are igored
        Pattern p = Pattern.compile(",(?=([^\"]*\"[^\"]*\")*(?![^\"]*\"))");
        //Execute the split
        String[] fields = p.split(line);
        for (int i = 0; i < fields.length; i++) {
            //Find the quotes and get rid of them, we don't want them in the table
            fields[i] = fields[i].replace("\"", "");
        }
        return fields;
    }
}