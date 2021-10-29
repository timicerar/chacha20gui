package sample.controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.input.KeyEvent;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import sample.implementation.ChaCha20;
import sample.implementation.utils.HelperUtils;
import sample.implementation.utils.KeyUtils;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

@SuppressWarnings({"unused"})
public class ChaChaController {

    @FXML
    private Button decryptButton;

    @FXML
    private Button decryptFileButton;

    @FXML
    private Label decryptFileLabel;

    @FXML
    private TextArea decryptedTextInput;

    @FXML
    private Button encryptButton;

    @FXML
    private Button encryptFileButton;

    @FXML
    private Label encryptFileLabel;

    @FXML
    private CheckBox encryptFromCheckBox;

    @FXML
    private TextArea encryptedTextInput;

    @FXML
    private Button generateKeyButton;

    @FXML
    private Button generateNonceButton;

    @FXML
    private Label keyLabel;

    @FXML
    private Button loadKeyButton;

    @FXML
    private Button loadNonceButton;

    @FXML
    private Label nonceLabel;

    @FXML
    private TextArea plainTextInput;

    @FXML
    private Button saveEncryptFileButton;

    @FXML
    private Button saveDecryptFileButton;

    @FXML
    private Button saveKeyButton;

    @FXML
    private Button saveNonceButton;

    private ChaCha20 chaCha20;
    private byte[] bytesOfFileToEncrypt;
    private byte[] bytesToDecrypt;
    private byte[] decryptedBytes;

    public void initialize() throws Exception {
        this.saveEncryptFileButton.setDisable(true);
        this.saveDecryptFileButton.setDisable(true);
        this.encryptButton.setDisable(true);
        this.decryptButton.setDisable(true);
        this.encryptedTextInput.setEditable(false);
        this.decryptedTextInput.setEditable(false);

        SecretKey key = KeyUtils.generateKey("ChaCha20", 256);
        byte[] nonce = KeyUtils.generateNonce(96);

        this.chaCha20 = new ChaCha20(key.getEncoded(), nonce);

        this.keyLabel.setText(chaCha20.getHexKey());
        this.nonceLabel.setText(chaCha20.getHexNonce());
    }

    @FXML
    void handleDecrypt(ActionEvent event) {
        if (this.bytesToDecrypt == null) {
            return;
        }

        byte[] decryptedData = this.chaCha20.decrypt(this.bytesToDecrypt, this.bytesToDecrypt.length);
        this.decryptedBytes = decryptedData;
        this.decryptedTextInput.setText(new String(decryptedData));
        this.saveDecryptFileButton.setDisable(false);
    }

    @FXML
    void handleEncrypt(ActionEvent event) {
        if (this.encryptFromCheckBox.isSelected()) {
            if (this.bytesOfFileToEncrypt == null) {
                return;
            }

            byte[] encryptedData = this.chaCha20.encrypt(this.bytesOfFileToEncrypt, this.bytesOfFileToEncrypt.length);
            this.bytesToDecrypt = encryptedData;
            this.encryptedTextInput.setText(HelperUtils.bytesToHex(encryptedData));
        } else {
            if (this.plainTextInput.getText() == null || this.plainTextInput.getText().length() <= 0) {
                return;
            }

            byte[] plainTextBytes = this.plainTextInput.getText().getBytes();
            byte[] encryptedData = this.chaCha20.encrypt(plainTextBytes, plainTextBytes.length);
            this.bytesToDecrypt = encryptedData;
            this.encryptedTextInput.setText(HelperUtils.bytesToHex(encryptedData));
        }

        this.saveEncryptFileButton.setDisable(false);
        this.decryptButton.setDisable(false);
    }

    @FXML
    void handleGenerateKey(ActionEvent event) throws NoSuchAlgorithmException {
        if (this.chaCha20 == null) {
            return;
        }

        SecretKey key = KeyUtils.generateKey("ChaCha20", 256);
        this.chaCha20.setKey(key.getEncoded());
        this.chaCha20.setInitialStateOfChaCha();
        this.keyLabel.setText(chaCha20.getHexKey());
    }

    @FXML
    void handleGenerateNonce(ActionEvent event) {
        if (this.chaCha20 == null) {
            return;
        }

        byte[] nonce = KeyUtils.generateNonce(96);
        this.chaCha20.setNonce(nonce);
        this.chaCha20.setInitialStateOfChaCha();
        this.nonceLabel.setText(chaCha20.getHexNonce());
    }

    @FXML
    void handleSaveKey(ActionEvent event) {
        if (this.chaCha20.getKey() == null) {
            return;
        }

        DirectoryChooser directoryChooser = new DirectoryChooser();
        File selectedDirectory = directoryChooser.showDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedDirectory == null) {
            return;
        }

        try {
            this.saveFile(this.chaCha20.getKey(), selectedDirectory.getAbsolutePath(), "chacha20-key-" + new Date().getTime());
            SHOW_ALERT("Key was successfully saved.", Alert.AlertType.INFORMATION);
        } catch (Exception e) {
            SHOW_ALERT("Oops. Something went wrong.", Alert.AlertType.WARNING);
        }
    }

    @FXML
    void handleSaveNonce(ActionEvent event) {
        if (this.chaCha20.getNonce() == null) {
            return;
        }

        DirectoryChooser directoryChooser = new DirectoryChooser();
        File selectedDirectory = directoryChooser.showDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedDirectory == null) {
            return;
        }

        try {
            this.saveFile(this.chaCha20.getNonce(), selectedDirectory.getAbsolutePath(), "chacha20-nonce-" + new Date().getTime());
            SHOW_ALERT("Nonce was successfully saved.", Alert.AlertType.INFORMATION);
        } catch (Exception e) {
            SHOW_ALERT("Oops. Something went wrong.", Alert.AlertType.WARNING);
        }
    }

    @FXML
    void handleLoadKey(ActionEvent event) throws IOException {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedFile == null) {
            return;
        }

        byte[] keyBytes = this.readFile(selectedFile);
        this.chaCha20.setKey(keyBytes);
        this.chaCha20.setInitialStateOfChaCha();
        this.keyLabel.setText(this.chaCha20.getHexKey());
    }

    @FXML
    void handleLoadNonce(ActionEvent event) throws IOException {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedFile == null) {
            return;
        }

        byte[] nonceBytes = this.readFile(selectedFile);
        this.chaCha20.setNonce(nonceBytes);
        this.chaCha20.setInitialStateOfChaCha();
        this.nonceLabel.setText(this.chaCha20.getHexNonce());
    }

    @FXML
    void handlePlainTextChange(KeyEvent event) {
        encryptButton.setDisable(this.bytesOfFileToEncrypt == null && (this.plainTextInput.getText() == null || this.plainTextInput.getText().trim().length() <= 0));
    }

    @FXML
    void handleSaveEncryptFile(ActionEvent event) {
        if (this.bytesToDecrypt == null || this.bytesToDecrypt.length <= 0) {
            return;
        }

        DirectoryChooser directoryChooser = new DirectoryChooser();
        File selectedDirectory = directoryChooser.showDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedDirectory == null) {
            return;
        }

        try {
            this.saveFile(this.bytesToDecrypt, selectedDirectory.getAbsolutePath(), "chacha20-encrypted-file-" + new Date().getTime());
            SHOW_ALERT("Encrypted file was successfully saved.", Alert.AlertType.INFORMATION);
        } catch (Exception e) {
            SHOW_ALERT("Oops. Something went wrong.", Alert.AlertType.WARNING);
        }
    }

    @FXML
    void handleSaveDecryptFile(ActionEvent event) {
        if (this.decryptedBytes == null || this.decryptedBytes.length <= 0) {
            return;
        }

        DirectoryChooser directoryChooser = new DirectoryChooser();
        File selectedDirectory = directoryChooser.showDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedDirectory == null) {
            return;
        }

        try {
            this.saveFile(this.decryptedBytes, selectedDirectory.getAbsolutePath(), "chacha20-decrypted-file-" + new Date().getTime());
            SHOW_ALERT("Decrypted file was successfully saved.", Alert.AlertType.INFORMATION);
        } catch (Exception e) {
            SHOW_ALERT("Oops. Something went wrong.", Alert.AlertType.WARNING);
        }
    }

    @FXML
    void handleSelectDecryptFile(ActionEvent event) throws IOException {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedFile == null) {
            return;
        }

        this.bytesToDecrypt = this.readFile(selectedFile);
        this.decryptFileLabel.setText(selectedFile.getName());
        this.decryptButton.setDisable(false);
        this.encryptedTextInput.setText(HelperUtils.bytesToHex(this.bytesToDecrypt));
    }

    @FXML
    void handleSelectEncryptFile(ActionEvent event) throws IOException {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(((Node) event.getTarget()).getScene().getWindow());

        if (selectedFile == null) {
            return;
        }

        this.bytesOfFileToEncrypt = this.readFile(selectedFile);
        this.encryptFileLabel.setText(selectedFile.getName());
        this.encryptButton.setDisable(false);
    }

    private void saveFile(final byte[] bytes, final String path, final String name) {
        File file = new File(path + "/" + name);

        try {
            OutputStream outputStream = new FileOutputStream(file);
            outputStream.write(bytes);
            outputStream.close();
        } catch (Exception e) {
            SHOW_ALERT("Oops. Something went wrong.", Alert.AlertType.WARNING);
        }
    }

    private byte[] readFile(final File file) throws IOException {
        return Files.readAllBytes(Paths.get(file.getAbsolutePath()));
    }

    private static void SHOW_ALERT(final String message, final Alert.AlertType alertType) {
        Alert alert = new Alert(alertType);
        String title = alertType.toString().substring(0, 1).toUpperCase() + alertType.toString().substring(1).toLowerCase();
        alert.setTitle(title + " dialog");
        alert.setHeaderText(title);
        alert.setContentText(message);
        alert.showAndWait();
    }
}