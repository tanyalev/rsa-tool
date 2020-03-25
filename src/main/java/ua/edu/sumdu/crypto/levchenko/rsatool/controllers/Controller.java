package ua.edu.sumdu.crypto.levchenko.rsatool.controllers;

import javafx.scene.control.Alert;
import javafx.stage.Stage;

public class Controller {
    protected Stage window;

    public void setWindow(Stage window) {
        this.window = window;
    }

    public void showWindow() {
        window.show();
    }

    protected void showWarningMessage(String message, String details) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("Warning");
        alert.setHeaderText(message);
        alert.setContentText(details);
        alert.setResizable(true);
        alert.showAndWait();
    }

    protected void showErrorMessage(String message, String details) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(message);
        alert.setContentText(details);
        alert.setResizable(true);
        alert.showAndWait();
    }
}