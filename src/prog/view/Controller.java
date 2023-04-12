package prog.view;

import javafx.application.Platform;
import javafx.stage.DirectoryChooser;
import prog.cipher.Cipher;
import prog.cipher.OperationMode;
import javafx.concurrent.Worker;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import prog.cipher.ThreadPool;

import java.io.File;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class Controller {

    @FXML
    private TextArea selectedFilesTextArea;
    @FXML
    private Button selectInput, selectOutput;
    @FXML
    private ToggleGroup operation, operationMode;
    @FXML
    private TextField outputFile;
    @FXML
    private PasswordField key;
    @FXML
    private Button run, GenerateKey;
    @FXML
    private RadioButton decrypt, encrypt;
    @FXML
    private RadioButton ecb, cbc, ofb, cfb;
    @FXML
    private ProgressBar progressBar;
    @FXML
    private TextArea status;
    private final List<File> selectedFiles = new ArrayList<>();
    private Cipher task;
    private File output;

    @FXML
    private void initialize() {
        outputFile.setText(System.getProperty("user.home").replace("\\", "/"));
        status.appendText("Select files, choose parameters and press run...");
    }

    /**
     * Select input file.
     */
    @FXML
    public void onSelectFilesBtnClicked() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select files");
        List<File> list = (fc.showOpenMultipleDialog(null));
        selectedFiles.clear();
        selectedFiles.addAll(list);
        updateSelectedFilesTextArea();
    }

    /**
     * Select output file.
     */
    @FXML
    private void onSelectDirBtnClicked() {
        File f = output != null ? selectDir(output.getParent()) :
                selectDir();
        if (f != null) {
            output = f;
            outputFile.setText(output.toString().replace("\\", "/"));
        }
    }

    /**
     * Open a FileChooser to select a file.
     *
     * @param path path to open
     * @return selected file
     */
    private File selectDir(String path) {
        Stage primaryStage = (Stage) outputFile.getScene().getWindow();
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setInitialDirectory(new File(path));
        chooser.setTitle("Select output");
        return chooser.showDialog(primaryStage);
    }

    /**
     * Open a FileChooser to select a file in the default path (user.home).
     */
    private File selectDir() {
        return selectDir(System.getProperty("user.home"));
    }
    private void updateSelectedFilesTextArea() {
        StringBuilder sb = new StringBuilder();
        for (File file : selectedFiles) {
            sb.append(file.getName())
                    .append(System.lineSeparator());
        }
        selectedFilesTextArea.setText(sb.toString());
    }

    /**
     * Run prog.cipher.
     */
    @FXML
    private void handleRun() {
        if(handleCancelTask()){
            blockUI(false);
            return;
        }
        if (selectedFiles.isEmpty()) {
            showError("no-file");
            return;
        } else if (key.getText().equals("")) {
            showError("no-key");
            return;
        }
        blockUI(true);
        boolean encrypt = (((RadioButton) operation.getSelectedToggle()).getText()).equals("Encrypt");
        OperationMode.Mode mode = switch (((RadioButton) operationMode.getSelectedToggle()).getText()) {
            case "ECB" -> OperationMode.Mode.ECB;
            case "CBC" -> OperationMode.Mode.CBC;
            case "CFB" -> OperationMode.Mode.CFB;
            case "OFB" -> OperationMode.Mode.OFB;
            default -> null;
        };
        resetStatus();
        ThreadPool pool = new ThreadPool(4);
        for(File in: selectedFiles) {
            File newFile = new File(output, in.getName());
            task = new Cipher(in.getPath(), newFile.getPath(), key.getText(), encrypt, mode);
            task.getStatus().addListener((observable, oldValue, newValue) -> Platform.runLater(() -> println(newValue)));
            task.setOnSucceeded(event -> blockUI(false));
            progressBar.progressProperty().bind(task.progressProperty());
            task.setOnFailed(event -> {
                if(task.getException() != null) {
                    println("Error: " + task.getException().getMessage());
                }
                blockUI(false);
            });
            pool.addTask(task);
        }
        pool.waitAllTasks();
        System.out.println("All tasks are completed");

        pool.stop();
        System.out.println("ThreadPool is stopped");
    }

    /**
     * Clear the status box.
     */
    private void resetStatus() {
        status.clear();
        status.appendText("Let's go!");
    }

    /**
     * Disable or enable the interface controls.
     *
     * @param running true: disable / false: enable
     */
    private void blockUI(boolean running) {
        if(running) {
            run.setText("Cancel");
        } else {
            run.setText("Run");
        }
        selectInput.setDisable(running);
        selectOutput.setDisable(running);
        ToggleGroup[] groups = {operation, operationMode};
        for(ToggleGroup g : groups){
            for (Toggle t : g.getToggles()) {
                if(t instanceof RadioButton){
                    ((RadioButton) t).setDisable(running);
                } else {
                    ((RadioMenuItem) t).setDisable(running);
                }
            }
        }
        key.setDisable(running);
    }

    /**
     * Generate Key.
     *
     */
    @FXML
    public void onGenerateKeyBtnClicked() {
        String generatedKey = generateKey();
        key.setText(generatedKey);
    }

    private static String generateKey() {
        final String CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        final int KEY_LENGTH = 16;
        SecureRandom random = new SecureRandom();
        StringBuilder key = new StringBuilder(KEY_LENGTH);
        for (int i = 0; i < KEY_LENGTH; i++) {
            int index = random.nextInt(CHARACTERS.length());
            char randomChar = CHARACTERS.charAt(index);
            key.append(randomChar);
        }
        return key.toString();
    }

    /**
     * Cancel task.
     *
     * @return true if the cancel was successful
     */
    private boolean handleCancelTask() {
        boolean canceled = false;
        if(task != null && task.getState() == Worker.State.RUNNING) {
            println("The operation was cancelled!");
            canceled = task.cancel();
        }
        return canceled;
    }

    private void println(String msg) {
        status.appendText("\n" + msg);
    }

    /**
     * Open an alert box to show the error.
     */
    private void showError(String error) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        if (error.equals("no-file")) {
            alert.setHeaderText("No file chosen");
            alert.setContentText("You have to choose the file to encrypt.");
        } else if (error.equals("no-key")) {
            alert.setHeaderText("No key");
            alert.setContentText("You have to enter a key.");
        }
        alert.showAndWait();
    }

}
