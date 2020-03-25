package ua.edu.sumdu.crypto.levchenko.rsatool.controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.Padding;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.Rsa;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.logging.Logger;

import static ua.edu.sumdu.crypto.levchenko.rsatool.Util.readFromFile;
import static ua.edu.sumdu.crypto.levchenko.rsatool.Util.writeToFile;

public class MainWindowController extends Controller implements Initializable {
    @FXML public TextField publicKeyTextField;
    @FXML public TextField privateKeyTextField;

    @FXML public Label publicKeySizeLabel;
    @FXML public Label publicKeySizeValueLabel;

    @FXML public Label privateKeySizeLabel;
    @FXML public Label privateKeySizeValueLabel;

    @FXML public TextArea textToEncryptTextArea;
    @FXML public TextArea textToDecryptTextArea;

    @FXML public TextArea encryptedTextTextArea;
    @FXML public TextArea decryptedTextTextArea;

    @FXML public CheckBox usePkcsPaddingCheckBox;
    @FXML public CheckBox pkcsPaddingUsedCheckBox;

    @FXML public Label statusLabel;

    @FXML public Button importTextToEncryptButton;
    @FXML public Button importTextToDecryptButton;

    @FXML public Button encryptButton;
    @FXML public Button decryptButton;

    @FXML public Button exportEncryptedTextButton;
    @FXML public Button exportDecryptedTextButton;

    private final static Logger log = Logger.getLogger(MainWindowController.class.getName());

    private GenerateKeyPairController generateKeyPairController;
    private AboutController aboutController;

    private KeyPair.PublicKey publicKey;
    private KeyPair.PrivateKey privateKey;

    public MainWindowController(GenerateKeyPairController generateKeyPairController, AboutController aboutController) {
        this.generateKeyPairController = generateKeyPairController;
        this.aboutController = aboutController;
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        setEncryptionPartDisable(true);
        setDecryptionPartDisable(true);

        log.info("Loaded.");
        statusLabel.setText("Loaded.");
    }

    @FXML
    public void quit(ActionEvent actionEvent) {
        window.close();
    }

    @FXML
    public void about(ActionEvent actionEvent) {
        aboutController.showWindow();
    }

    @FXML
    public void generateKeyPair(ActionEvent actionEvent) {
        generateKeyPairController.showWindow();
        statusLabel.setText("New key pair generated.");
    }

    @FXML
    public void importPublicKey(ActionEvent actionEvent) {
        OpenedFile publicKeyFile = openFile(new FileChooser.ExtensionFilter("Public key", "*_pub.key"));
        if (!publicKeyFile.isEmpty()) {
            publicKey = KeyPair.PublicKey.fromRawData(publicKeyFile.getData());
            publicKeySizeLabel.setVisible(true);
            publicKeySizeValueLabel.setText(String.valueOf(publicKey.getSize()));
            publicKeyTextField.setText(publicKeyFile.getName());
            setEncryptionPartDisable(false);
            statusLabel.setText(String.format("Imported public key from \"%s\"", publicKeyFile.getName()));
        }
    }

    @FXML
    public void importPrivateKey(ActionEvent actionEvent) {
        OpenedFile privateKeyFile = openFile(new FileChooser.ExtensionFilter("Private key", "*_priv.key"));
        if (!privateKeyFile.isEmpty()) {
            privateKey = KeyPair.PrivateKey.fromRawData(privateKeyFile.getData());
            privateKeySizeLabel.setVisible(true);
            privateKeySizeValueLabel.setText(String.valueOf(privateKey.getSize()));
            privateKeyTextField.setText(privateKeyFile.getName());
            setDecryptionPartDisable(false);
            statusLabel.setText(String.format("Imported private key from \"%s\"", privateKeyFile.getName()));
        }
    }

    @FXML
    public void importTextToEncrypt(ActionEvent actionEvent) {
        OpenedFile dataFile = openFile(new FileChooser.ExtensionFilter("Any file", "*"));
        if (!dataFile.isEmpty()) {
            textToEncryptTextArea.setText(dataFile.getData());
            statusLabel.setText(String.format("Text to encrypt imported from \"%s\"", dataFile.getName()));
        }
    }

    @FXML
    public void importTextToDecrypt(ActionEvent actionEvent) {
        OpenedFile dataFile = openFile(new FileChooser.ExtensionFilter("Any file", "*"));
        if (!dataFile.isEmpty()) {
            textToDecryptTextArea.setText(dataFile.getData());
            boolean paddingUsed = Rsa.Message.fromRawData(dataFile.getData()).getPadding().equals(Padding.PKCS1.name());
            pkcsPaddingUsedCheckBox.setSelected(paddingUsed);
            statusLabel.setText(String.format("Text to decrypt imported from \"%s\"", dataFile.getName()));
        }
    }

    @FXML
    public void encrypt(ActionEvent actionEvent) {
        String textToEncrypt = textToEncryptTextArea.getText();
        if (Objects.isNull(textToEncrypt) || textToEncrypt.isEmpty() || textToEncrypt.isBlank()) {
            showWarningMessage("No text to encrypt", "Enter text to encrypt!");
            return;
        }

        try {
            boolean usePadding = usePkcsPaddingCheckBox.isSelected();
            Rsa rsa = new Rsa();
            rsa.setPadding(usePadding ? Padding.PKCS1 : Padding.NONE);
            Rsa.Message message = rsa.encrypt(publicKey, textToEncrypt);
            String rawEncryptedData = message.toRawData();
            encryptedTextTextArea.setText(rawEncryptedData);
            statusLabel.setText("Text has been encrypted!");
        } catch (Exception e) {
            log.severe(String.format("Error encrypting data: %s", e.getMessage()));
            showErrorMessage("Error encrypting data", Arrays.toString(e.getStackTrace()));
        }
    }

    @FXML
    public void decrypt(ActionEvent actionEvent) {
        String textToDecrypt = textToDecryptTextArea.getText();
        if (Objects.isNull(textToDecrypt) || textToDecrypt.isEmpty() || textToDecrypt.isBlank()) {
            showWarningMessage("No text to decrypt", "Enter text to decrypt!");
            return;
        }

        try {
            Rsa.Message message = Rsa.Message.fromRawData(textToDecrypt);
            Rsa rsa = new Rsa();
            rsa.setPadding(Padding.valueOf(message.getPadding()));
            String decryptedData = rsa.decrypt(privateKey, message);
            decryptedTextTextArea.setText(decryptedData);
            statusLabel.setText("Text has been decrypted!");
        } catch (Exception e) {
            log.severe(String.format("Error decrypting data: %s", e.getMessage()));
            showErrorMessage("Error decrypting data", Arrays.toString(e.getStackTrace()));
        }
    }

    @FXML
    public void exportEncryptedText(ActionEvent actionEvent) {
        String encryptedText = encryptedTextTextArea.getText();
        if (!encryptedText.isBlank() && !encryptedText.isEmpty()) {
            saveToFile(encryptedText);
            statusLabel.setText("Encrypted text saved to file.");
        }
    }

    @FXML
    public void exportDecryptedText(ActionEvent actionEvent) {
        String decryptedText = decryptedTextTextArea.getText();
        if (!decryptedText.isBlank() && !decryptedText.isEmpty()) {
            saveToFile(decryptedText);
            statusLabel.setText("Decrypted text saved to file.");
        }
    }

    private void setEncryptionPartDisable(boolean disable) {
        textToEncryptTextArea.setDisable(disable);
        importTextToEncryptButton.setDisable(disable);
        encryptButton.setDisable(disable);
        exportEncryptedTextButton.setDisable(disable);
        usePkcsPaddingCheckBox.setDisable(disable);
    }

    private void setDecryptionPartDisable(boolean disable) {
        textToDecryptTextArea.setDisable(disable);
        importTextToDecryptButton.setDisable(disable);
        decryptButton.setDisable(disable);
        exportDecryptedTextButton.setDisable(disable);
        privateKeySizeLabel.setVisible(disable);
    }

    private OpenedFile openFile(FileChooser.ExtensionFilter filter) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Choose file to open");
        fileChooser.getExtensionFilters().add(filter);
        File file = fileChooser.showOpenDialog(window);
        if (Objects.isNull(file)) {
            return new OpenedFile();
        }

        String filename = file.getAbsolutePath();

        try {
            return new OpenedFile(filename, readFromFile(filename));
        } catch (Exception e) {
            log.severe(String.format("Error reading data from file \"%s\": %s", filename, e.getMessage()));
            showErrorMessage(String.format("Error reading data from file \"%s\"", filename),
                    Arrays.toString(e.getStackTrace()));
        }

        return new OpenedFile();
    }

    private void saveToFile(String data) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save data to file");
        File file = fileChooser.showSaveDialog(window);
        if (Objects.isNull(file)) {
            return;
        }

        String filename = file.getAbsolutePath();

        try {
            writeToFile(filename, data);
        } catch (Exception e) {
            log.severe(String.format("Error writing data to file \"%s\": %s", filename, e.getMessage()));
            showErrorMessage(String.format("Error writing data to file \"%s\"", filename),
                    Arrays.toString(e.getStackTrace()));
        }
    }
}

