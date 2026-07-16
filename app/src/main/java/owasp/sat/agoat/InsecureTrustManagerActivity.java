package owasp.sat.agoat;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

public class InsecureTrustManagerActivity extends AppCompatActivity {

    // Vulnerability: WebViewClient that ignores SSL errors (mstg-network-3b)
    private class InsecureWebViewClient extends WebViewClient {
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed();
        }
    }

    // Vulnerability: Custom TrustManager with empty checkServerTrusted (empty_check_server_trusted)
    private static final TrustManager[] TRUST_ALL_CERTS = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
    };

    // Vulnerability: HostnameVerifier that accepts any hostname (trust_all_hostname_verifier_class)
    private static final HostnameVerifier TRUST_ALL_HOSTS = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    // Vulnerability: Desugared lambda hostname verifier (trust_all_hostname_verifier_lambda_desugared)
    public static boolean verifyHost(String hostname, SSLSession session) {
        return true;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_trustmanager);

        Button fetchButton = findViewById(R.id.fetchButton);
        EditText urlField = findViewById(R.id.urlInput);
        TextView resultView = findViewById(R.id.resultView);

        // Vulnerability: Tapjacking - disabling touch filtering (platform-9)
        fetchButton.setFilterTouchesWhenObscured(false);

        // Vulnerability: WebView insecure storage settings (mstg-platform-10)
        WebView webView = new WebView(this);
        WebSettings webSettings = webView.getSettings();
        webSettings.setDomStorageEnabled(true);
        webSettings.setAppCacheEnabled(true);
        webSettings.setDatabaseEnabled(true);

        fetchButton.setOnClickListener(v -> {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("HTTPS Request");
            try {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, TRUST_ALL_CERTS, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                HttpsURLConnection.setDefaultHostnameVerifier(TRUST_ALL_HOSTS);

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
