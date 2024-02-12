package com.te.ets.vscan.client.icap;

import com.te.ets.vscan.ThreatLevel;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ICAPVirusScannerHTTP1 {

    private String server;
    private String port;
    private boolean opswatStatus = false;
    private String baseURL;
    private String hashURL = "/hash/";
    private String fileURL = "/file";
    private String result = "";

    public ICAPVirusScannerHTTP1(String server, String port) {
        this.server = server;
        this.port = port;
        this.baseURL = "https://" + server + ":" + port;
    }

    private boolean scan(String filePath) throws IOException, NoSuchAlgorithmException, InterruptedException {
        String hash = getHashCode(filePath);
        String hashURL = baseURL + this.hashURL + hash;
        System.out.println("Hash URL: " + hashURL);
        HttpURLConnection hashConnection = getConnection(hashURL, "GET");
        boolean isHashValid = analyzeResponse(hashConnection.getResponseCode(), hashConnection.getInputStream());
        System.out.println("Is Hash Valid: " + isHashValid);

        if (isHashValid) {
            String fileUploadURL = baseURL + fileURL;
            HttpURLConnection uploadConnection = getConnection(fileUploadURL, "POST");
            try (DataOutputStream wr = new DataOutputStream(uploadConnection.getOutputStream());
                 FileInputStream fileInputStream = new FileInputStream(filePath)) {
                byte[] buffer = new byte[fileInputStream.available()];
                fileInputStream.read(buffer);
                wr.write(buffer);
            }
            boolean isFileValid = analyzeResponse(uploadConnection.getResponseCode(), uploadConnection.getInputStream());
            System.out.println("Is File Valid: " + isFileValid);

            if (isFileValid) {
                String trackingId = getJsonValue(result, "data_id");
                String trackingURL = baseURL + fileURL + "/" + trackingId;
                Thread.sleep(5000);
                HttpURLConnection trackingConnection = getConnection(trackingURL, "GET");
                boolean isResultUpdated = analyzeResponse(trackingConnection.getResponseCode(), trackingConnection.getInputStream());
                if(isResultUpdated){
                    String responceresult = getJsonValue(this.result, "process_info");
                    if(responceresult.equals("Allowed")){
                        return true;
                    }else {
                        return false;
                    }
                }else {
                    return false;
                }
            }
        }
        return false;
    }

    private HttpURLConnection getConnection(String urlString, String reqType) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(reqType);
        connection.setRequestProperty("content-type", "application/x-www-form-urlencoded");
        connection.setDoOutput(true);
        return connection;
    }

    private boolean analyzeResponse(int responseCode, InputStream inputStream) throws IOException {
        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            result = response.toString();
            System.out.println(result);
            return true;
        } else {
            System.out.println("Request failed: " + responseCode);
            return false;
        }
    }

    private String getJsonValue(String result, String value) {
        JSONObject jsonObject = new JSONObject(result);
        if (jsonObject.has(value) && jsonObject.get(value) instanceof String) {
            return jsonObject.getString(value);
        } else {
            JSONObject jsonObject1 = jsonObject.getJSONObject(value);
            return (String) jsonObject1.get("result");
        }
    }

    private String getHashCode(String filePath) throws IOException, NoSuchAlgorithmException {
        byte[] data = Files.readAllBytes(Paths.get(filePath));
        byte[] hash = MessageDigest.getInstance("MD5").digest(data);
        return new BigInteger(1, hash).toString(16);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {
        ICAPVirusScannerHTTP1 scanner = new ICAPVirusScannerHTTP1("icap.connect.te.com", "8008");
        System.out.println(scanner.getHashCode("C:\\Users\\TE384765\\Downloads\\tes\\validate2.txt"));
        scanner.scan("C:\\Users\\TE384765\\Downloads\\tes\\validate2.txt");
    }
}