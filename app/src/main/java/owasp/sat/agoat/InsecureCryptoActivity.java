package owasp.sat.agoat;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class InsecureCryptoActivity extends AppCompatActivity {

    // Vulnerability: Hardcoded key as byte array class field
    byte[] hardcodedKey = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    // Vulnerability: Hardcoded IV string and derived byte array
    String ivString = "1234567890abcdef";
    byte[] ivBytes = ivString.getBytes();

    // Vulnerability: Hardcoded key string
    String secretString = "MySecretKey12345";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_crypto);

        Button encryptButton = findViewById(R.id.encryptButton);
        EditText inputField = findViewById(R.id.inputData);
        TextView resultView = findViewById(R.id.resultView);

        encryptButton.setOnClickListener(v -> {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Encryption");
            try {
                String plaintext = inputField.getText().toString();

                // Vulnerability 1: SecretKeySpec with hardcoded byte array class field
                SecretKeySpec keySpec1 = new SecretKeySpec(hardcodedKey, "AES");

                // Vulnerability 2: IvParameterSpec with hardcoded byte array from string
                IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

                // Vulnerability 3: SecretKeySpec with inline byte array
                SecretKeySpec keySpec2 = new SecretKeySpec(new byte[]{0x41, 0x42, 0x43, 0x44,
                        0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50}, "AES");

                // Vulnerability 4: SecretKeySpec with getBytes() from hardcoded string
                SecretKeySpec keySpec3 = new SecretKeySpec(secretString.getBytes(), "AES");

                // Vulnerability 5: IvParameterSpec with inline byte array
                IvParameterSpec ivSpec2 = new IvParameterSpec(new byte[]{0x00, 0x01, 0x02, 0x03,
                        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F});

                // Vulnerability 6: Insecure RNG using SHA1PRNG
                SecureRandom insecureRng = SecureRandom.getInstance("SHA1PRNG");
                insecureRng.setSeed(hardcodedKey);

                // Vulnerability 7: Weak cipher algorithms stored in config map (mstg-crypto-4)
                Map<String, String> cryptoConfig = new HashMap<>();
                cryptoConfig.put("ecbCipher", "AES/ECB/PKCS5Padding");
                cryptoConfig.put("desCipher", "DES/CBC/PKCS5Padding");
                cryptoConfig.put("tripleDesCipher", "DESede/3DES/NoPadding");
                cryptoConfig.put("rc4Cipher", "RC4/None/NoPadding");
                cryptoConfig.put("blowfishCipher", "Blowfish/BLOWFISH/PKCS5Padding");
                cryptoConfig.put("hashAlgo", "MD5/digest");
                cryptoConfig.put("legacyHash", "SHA1/digest");
                cryptoConfig.put("rc2Cipher", "RC2/CBC/PKCS5Padding");

                // Vulnerability 8: Using ECB mode cipher
                Cipher ecbCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                ecbCipher.init(Cipher.ENCRYPT_MODE, keySpec1);

                // Vulnerability 9: Using DES weak cipher
                SecretKeySpec desKey = new SecretKeySpec(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, "DES");
                Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

                // Vulnerability 10: Using MD5 weak hash
                MessageDigest md5Digest = MessageDigest.getInstance("MD5");
                md5Digest.update(plaintext.getBytes());

                // Vulnerability 11: NullCipher - ciphertext identical to plaintext
                NullCipher nullCipher = new NullCipher();
                byte[] nullEncrypted = nullCipher.doFinal(plaintext.getBytes());

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec1, ivSpec);
                byte[] encrypted = cipher.doFinal(plaintext.getBytes());
                String encodedResult = Base64.getEncoder().encodeToString(encrypted);

                resultView.setText("Encrypted: " + encodedResult);
                builder.setMessage("Data encrypted successfully using hardcoded key");
                Toast.makeText(getApplicationContext(), "Data encrypted", Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                builder.setMessage("Encryption failed");
                Toast.makeText(getApplicationContext(), "Encryption failed", Toast.LENGTH_LONG).show();
                e.printStackTrace();
            }
            builder.setPositiveButton("OK", (dialog, which) -> dialog.dismiss());
            builder.create().show();
        });
    }
}
