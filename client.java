package ml_project.cn;

import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.swing.*;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;

public class client extends JFrame {
    private final JTextField fileField = new JTextField(24);
    private final JButton browseBtn = new JButton("Browse");
    private final JComboBox<String> algoCombo = new JComboBox<>(new String[] {"AES-256"});
    private final JTextField ipField = new JTextField("127.0.0.1", 12);
    private final JTextField portField = new JTextField("8080", 6);
    private final JButton sendBtn = new JButton("Send File");
    private final JProgressBar progressBar = new JProgressBar(0,100);
    private final JTextArea statusArea = new JTextArea(8, 40);

    private File selectedFile;

    public client() {
        super("Secure File Transfer - Client");
        initUI();
    }

    private void initUI() {
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6,6,6,6);

        // Row: Select File label, Browse, path
        gbc.gridx=0; gbc.gridy=0;
        add(new JLabel("Select File"), gbc);
        gbc.gridx=1;
        add(browseBtn, gbc);
        gbc.gridx=2;
        fileField.setEditable(false);
        add(fileField, gbc);

        // Row: Encryption Algorithm
        gbc.gridx=0; gbc.gridy=1;
        add(new JLabel("Encryption Algorithm"), gbc);
        gbc.gridx=1; gbc.gridwidth=2;
        add(algoCombo, gbc);
        gbc.gridwidth=1;

        // Row: Server IP and Port
        gbc.gridx=0; gbc.gridy=2;
        add(new JLabel("Server IP"), gbc);
        gbc.gridx=1;
        add(ipField, gbc);
        gbc.gridx=2;
        add(portField, gbc);

        // Row: Send Button
        gbc.gridx=1; gbc.gridy=3;
        add(sendBtn, gbc);

        // Row: Progress bar
        gbc.gridx=0; gbc.gridy=4; gbc.gridwidth=3; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(progressBar, gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.gridwidth=1;

        // Status area
        gbc.gridx=0; gbc.gridy=5; gbc.gridwidth=3;
        add(new JScrollPane(statusArea), gbc);
        statusArea.setEditable(false);

        browseBtn.addActionListener(this::onBrowse);
        sendBtn.addActionListener(this::onSend);

        pack();
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    private void onBrowse(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        int ret = fc.showOpenDialog(this);
        if (ret == JFileChooser.APPROVE_OPTION) {
            selectedFile = fc.getSelectedFile();
            fileField.setText(selectedFile.getAbsolutePath());
            log("Selected: " + selectedFile.getName() + " (" + selectedFile.length() + " bytes)");
        }
    }

    private void onSend(ActionEvent e) {
        if (selectedFile == null || !selectedFile.exists()) {
            JOptionPane.showMessageDialog(this, "Please select a valid file.");
            return;
        }
        sendBtn.setEnabled(false);
        new Thread(() -> {
            try {
                sendFile();
            } catch (Exception ex) {
                log("Error: " + ex.getMessage());
                ex.printStackTrace();
            } finally {
                SwingUtilities.invokeLater(() -> sendBtn.setEnabled(true));
            }
        }).start();
    }

    private void sendFile() throws Exception {
        String host = ipField.getText().trim();
        int port = Integer.parseInt(portField.getText().trim());

        try (Socket socket = new Socket(host, port);
             DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
             DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()))) {

            log("Connected to " + host + ":" + port);

            // Read server RSA public key
            int pubLen = in.readInt();
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);
            PublicKey serverPub = Crypto.publicKeyFromBytes(pubBytes);
            log("Received server public key (" + pubLen + " bytes).");
            log("Recieved ASE Encrypted key");
            System.out.println(serverPub);
            // Generate AES key and IV
            SecretKey aesKey = Crypto.generateAESKey();
            byte[] aesKeyBytes = aesKey.getEncoded();
            byte[] encAesKey = Crypto.rsaEncrypt(aesKeyBytes, serverPub);

            byte[] iv = new byte[Crypto.GCM_IV_LENGTH];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(iv);

            // Send encrypted AES key
            out.writeInt(encAesKey.length);
            out.write(encAesKey);

            // Send IV
            out.writeInt(iv.length);
            out.write(iv);

            // Filename
            byte[] fnameBytes = selectedFile.getName().getBytes("UTF-8");
            out.writeInt(fnameBytes.length);
            out.write(fnameBytes);

            long originalSize = selectedFile.length();
            long encryptedSize = originalSize + Crypto.GCM_TAG_LENGTH; // GCM tag appended

            out.writeLong(originalSize);
            out.writeLong(encryptedSize);
            out.flush();

            log("Sending file: " + selectedFile.getName() + " (" + originalSize + " bytes)");

            // Stream file encrypted with AES/GCM
            Cipher encryptCipher = Crypto.createAESCipher(Cipher.ENCRYPT_MODE, aesKey, iv);

            try (FileInputStream fis = new FileInputStream(selectedFile);
                 CipherOutputStream cos = new CipherOutputStream(out, encryptCipher)) {

                byte[] buf = new byte[8192];
                long total = 0;
                int r;
                while ((r = fis.read(buf)) != -1) {
                    cos.write(buf, 0, r);
                    total += r;
                    final int pct = (int)((total * 100) / originalSize);
                    SwingUtilities.invokeLater(() -> progressBar.setValue(pct));
                }
                cos.flush(); // important to ensure GCM tag is written
            }

            out.flush();
            log("Upload complete.");
            SwingUtilities.invokeLater(() -> progressBar.setValue(100));
        }
    }

    private void log(String s) {
        SwingUtilities.invokeLater(() -> {
            statusArea.append(s + "\n");
            statusArea.setCaretPosition(statusArea.getDocument().getLength());
        });
        System.out.println("[CLIENT] " + s);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            client client = new client();
            client.setVisible(true);
        });
    }
}
