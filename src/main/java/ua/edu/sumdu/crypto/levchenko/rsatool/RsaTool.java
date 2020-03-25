package ua.edu.sumdu.crypto.levchenko.rsatool;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Modality;
import javafx.stage.Stage;
import ua.edu.sumdu.crypto.levchenko.rsatool.controllers.AboutController;
import ua.edu.sumdu.crypto.levchenko.rsatool.controllers.Controller;
import ua.edu.sumdu.crypto.levchenko.rsatool.controllers.GenerateKeyPairController;
import ua.edu.sumdu.crypto.levchenko.rsatool.controllers.MainWindowController;

import java.io.IOException;

public class RsaTool extends Application {
    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) throws Exception {
        MainWindowController mainController = new MainWindowController(
                getController("/views/generatekeypair.fxml", "Generate key pair", new GenerateKeyPairController()),
                getController("/views/about.fxml", "About", new AboutController()));

        FXMLLoader loader = new FXMLLoader();
        loader.setController(mainController);
        loader.setLocation(getClass().getResource("/views/main.fxml"));
        Parent content = loader.load();

        stage.setTitle("RSA Tool");
        stage.setResizable(false);
        stage.setScene(new Scene(content));
        stage.getIcons().add(new Image(getClass().getResourceAsStream("/icons/rsa.png")));

        mainController.setWindow(stage);
        mainController.showWindow();
    }

    private <C extends Controller> C getController(String filename, String title, C controller) throws IOException {
        Stage window = new Stage();
        controller.setWindow(window);
        FXMLLoader loader = new FXMLLoader(getClass().getResource(filename));
        loader.setController(controller);
        Parent parent = loader.load();

        window.initModality(Modality.APPLICATION_MODAL);
        window.setTitle(title);
        window.setResizable(false);
        window.setScene(new Scene(parent));
        return controller;
    }
}
