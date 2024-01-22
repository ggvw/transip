import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;

public class TransIPUpdater {

    private static final String LOGIN = "";
    private static final String PRIVATE_KEY = readPrivateKey();
    private static final String ENDPOINT = "api.transip.nl";
    private static final String VERSION = "v6";
    private static final String AUTH_URL = String.format("https://%s/%s/auth", ENDPOINT, VERSION);
    private static final String EXPIRATION_TIME = "60 seconds";
    private static final String DOMAIN = "ggvw.nl";
    private static final String SUBDOMAIN = "@";
    private static final boolean READ_ONLY = false;
    private static final boolean GLOBAL_KEY = true;

    public static void main(String[] args) {
        try {
            String currentIP = getCurrentPublicIP();
            System.out.println("Current IP: " + currentIP);

            String token = authenticateWithTransIP();
            System.out.println("Authentication Token: " + token);

            updateDNSRecord(token, currentIP);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getCurrentPublicIP() throws IOException {
        URL url = new URL("https://api.ipify.org");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            return reader.readLine();
        }
    }

    private static String authenticateWithTransIP() throws Exception {
        JSONObject requestBody = new JSONObject();
        requestBody.put("login", LOGIN);
        requestBody.put("nonce",   Long.valueOf(System.currentTimeMillis()).toString());
        requestBody.put("read_only", READ_ONLY);
        requestBody.put("expiration_time", EXPIRATION_TIME);
        requestBody.put("label", "Java API Client " + LocalDateTime.now().toString());
        requestBody.put("global_key", GLOBAL_KEY);

        String signature = createSignature(requestBody.toString());
        return performAuthRequest(requestBody.toString(), signature);
    }

    private static String createSignature(String parameters) throws Exception {
        // Remove the markers and new lines from privateKey
        String privateKeyPEM = PRIVATE_KEY.trim()
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(privateKey);
        signature.update(parameters.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static String performAuthRequest(String requestBody, String signature) throws IOException {
        URL url = new URL(AUTH_URL);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Signature", signature);
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = requestBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
            os.flush();
        }
        if (conn.getResponseCode() >=300) {
            printErrors(conn);
        }

        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            JSONObject jsonResponse = new JSONObject(response.toString());
            return jsonResponse.getString("token");
        }
    }

    private static void printErrors(HttpsURLConnection conn) throws IOException {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            System.out.println(response.toString());
        }
    }

    private static void updateDNSRecord(String token, String ip) throws IOException {
        // Construct the URL for the DNS API endpoint
        String dnsApiUrl = "https://api.transip.nl/v6/domains/" + DOMAIN + "/dns"; // Replace with actual URL
        // Set up the DNS record update request body
        JSONObject subdomainEntry = new JSONObject();
        subdomainEntry.put("name", SUBDOMAIN);
        subdomainEntry.put("expire", 60);
        subdomainEntry.put("type", "A");
        subdomainEntry.put("content", ip);

        JSONObject json = new JSONObject();
        json.put("dnsEntry",subdomainEntry);

        System.out.println("Using " + dnsApiUrl + " doing PATCH" );
        System.out.println(json );
        System.out.println("Using " + dnsApiUrl + " doing PATCH");
        System.out.println(json);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(dnsApiUrl))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(json.toString(), StandardCharsets.UTF_8))
                .build();

        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 300) {
                System.out.println("DNS record updated successfully.");
            } else {
                System.out.println("Failed to update DNS record. Response Code: " + response.statusCode());
                // You can print response body for debugging
                System.out.println("Response Body: " + response.body());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String readPrivateKey()   {
        ClassLoader classLoader = TransIPUpdater.class.getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("transip.key");
        try {
            String data = new String(inputStream.readAllBytes());
            return data;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
