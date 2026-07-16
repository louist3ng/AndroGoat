package owasp.sat.agoat;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;

public class InsecureStorageLocalWriteActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_storage_local_write);

        Button saveButton = findViewById(R.id.localWriteSaveButton);
        EditText usernameField = findViewById(R.id.userName);
        EditText passwordField = findViewById(R.id.password);
        EditText apiKeyField = findViewById(R.id.apiKey);

        saveButton.setOnClickListener(v -> {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Save Credentials");
            try {
                String username = usernameField.getText().toString();
                String pwd = passwordField.getText().toString();
                String api_key = apiKeyField.getText().toString();

                // Vulnerable: Writing sensitive data via Writer to local file
                File credFile = new File(getApplicationInfo().dataDir, "user_creds.txt");
                Writer credWriter = new FileWriter(credFile);
                credWriter.write(username);
                credWriter.write(pwd);
                credWriter.write(api_key);
                credWriter.close();

                // Vulnerable: Writing sensitive data via OutputStream to local file
                File secretFile = new File(getApplicationInfo().dataDir, "secret_store.bin");
                OutputStream secretStream = new FileOutputStream(secretFile);
                byte[] cred = (username + ":" + pwd).getBytes();
                secretStream.write(cred);
                secretStream.close();

                builder.setMessage("Credentials saved to local storage successfully");
                Toast.makeText(getApplicationContext(), "Credentials saved to local storage", Toast.LENGTH_LONG).show();
            } catch (IOException e) {
                builder.setMessage("Error saving credentials to local storage");
                Toast.makeText(getApplicationContext(), "Error saving credentials", Toast.LENGTH_LONG).show();
                e.printStackTrace();
            }
            builder.setPositiveButton("OK", (dialog, which) -> dialog.dismiss());
            builder.create().show();
        });
    }
}
