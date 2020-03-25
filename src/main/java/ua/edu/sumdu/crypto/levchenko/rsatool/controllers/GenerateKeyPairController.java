package ua.edu.sumdu.crypto.levchenko.rsatool.controllers;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextField;
import javafx.stage.DirectoryChooser;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.RsaKeyPairGenerator;

import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

import static ua.edu.sumdu.crypto.levchenko.rsatool.Util.writeToFile;

public class GenerateKeyPairController extends Controller {
    @FXML public TextField keyPairNameTextField;
    @FXML public ComboBox<Integer> keySizeComboBox;
    @FXML public TextField directoryTextField;

    private final ObservableList<Integer> keySizes = FXCollections.observableArrayList(List.of(512, 1024, 2048, 4096));

    private final static Logger log = Logger.getLogger(GenerateKeyPairController.class.getName());

    private String directory = "";

    @Override
    public void showWindow() {
        keySizeComboBox.setItems(keySizes);
        super.showWindow();
    }

    @FXML
    public void chooseDirectory(ActionEvent actionEvent) {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        File selectedDirectory = directoryChooser.showDialog(window);
        directory = selectedDirectory.getAbsolutePath();
        directoryTextField.setText(directory);
    }

    private boolean isFull(String string) {
        return !string.isBlank() && !string.isEmpty();
    }

    @FXML
    public void generateAndSave(ActionEvent actionEvent) {
        boolean keyPairNameFilledUp = isFull(keyPairNameTextField.getText());
        boolean keySizeIsSelected = Objects.nonNull(keySizeComboBox.getSelectionModel().getSelectedItem());
        boolean directoryIsSelected = isFull(directoryTextField.getText());
        boolean allFieldsFilledUp = keyPairNameFilledUp && keySizeIsSelected && directoryIsSelected;

        if (!allFieldsFilledUp) {
            showWarningMessage("Empty fields", "Please, fill all fields!");
            return;
        }

        String file = Path.of(directory, keyPairNameTextField.getText()).toString();
        int keySize = keySizeComboBox.getSelectionModel().getSelectedItem();

        RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
        KeyPair keyPair = keyPairGenerator.generateKeyPair(keySize);

        String rawPublicKey = keyPair.getPublicKey().toRawData();
        String rawPrivateKey = keyPair.getPrivateKey().toRawData();

        String publicKeyFilename = String.format("%s_pub.key", file.strip());
        String privateKeyFilename = String.format("%s_priv.key", file.strip());

        try {
            writeToFile(publicKeyFilename, rawPublicKey);
            writeToFile(privateKeyFilename, rawPrivateKey);
        } catch (Exception e) {
            showErrorMessage("Error writing key pair to file", Arrays.toString(e.getStackTrace()));
            log.severe(String.format("Error writing key pair to file \"%s\": %s", file, e.getMessage()));
        }

        log.info(String.format("Key pair generated: \"%s\", \"%s\"", publicKeyFilename, privateKeyFilename));

        window.close();
    }
}
