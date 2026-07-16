package owasp.sat.agoat;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

public class InsecureTrustManagerActivity extends AppCompatActivity {

    // Vulnerability: Custom TrustManager that trusts all certificates (mstg-network-3a)
    private static final TrustManager[] TRUST_ALL_CERTS = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // Empty: accepts any client certificate
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // Empty: accepts any server certificate
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_trustmanager);

        Button fetchButton = findViewById(R.id.fetchButton);
        EditText urlField = findViewById(R.id.urlInput);
        TextView resultView = findViewById(R.id.resultView);

        fetchButton.setOnClickListener(v -> {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("HTTPS Request");
            try {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, TRUST_ALL_CERTS, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

                URL url = new URL(urlField.getText().toString());
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                resultView.setText(response.toString());
                builder.setMessage("Request completed with trust-all TrustManager");
                Toast.makeText(getApplicationContext(), "Request completed", Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                builder.setMessage("Request failed");
                Toast.makeText(getApplicationContext(), "Request failed", Toast.LENGTH_LONG).show();
                e.printStackTrace();
            }
            builder.setPositiveButton("OK", (dialog, which) -> dialog.dismiss());
            builder.create().show();
        });
    }
}
