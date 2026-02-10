package ml_project.cn;

import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import javax.crypto.Cipher;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class server extends JFrame {
    private final JTextField portField = new JTextField("8080", 6);
    private final JButton startBtn = new JButton("Start Server");
    private final JTextField statusField = new JTextField("Stopped");
    private final JTextArea logArea = new JTextArea(12, 40);
    private final JButton decryptBtn = new JButton("Decrypt File"); 
    
    private ServerSocket serverSocket;
    private volatile boolean running = false;
    private ExecutorService pool = Executors.newCachedThreadPool();
    private KeyPair rsaKeyPair;
    private final File saveDir = new File("received");

    // Fields to hold necessary decryption data until the button is clicked
    private SecretKey pendingAesKey = null;
    private byte[] pendingIv = null;
    private String encryptedFilePath = null;
    private String decryptedFileName = null;
    private long pendingEncryptedSize = 0;


    public server() {
        super("Secure File Transfer - Server");
        initUI();
        saveDir.mkdirs();
        decryptBtn.setEnabled(false); // Start disabled
    }

    private void initUI() {
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.insets = new Insets(6,6,6,6);

        // Top row: Start button, Port, Status
        gbc.gridx = 0; gbc.gridy = 0;
        add(startBtn, gbc);

        gbc.gridx = 1;
        add(new JLabel("Port:"), gbc);

        gbc.gridx = 2;
        add(portField, gbc);

        gbc.gridx = 3;
        add(new JLabel("Status:"), gbc);

        gbc.gridx = 4;
        statusField.setEditable(false);
        statusField.setColumns(18);
        add(statusField, gbc);

        // Decrypt Button below controls
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
        add(decryptBtn, gbc);

        // Log area below the controls (spanning 5 columns)
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 5; 
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0; 
        gbc.weighty = 1.0; 
        add(new JScrollPane(logArea), gbc);
        logArea.setEditable(false);

        // FIX Applied: Using Anonymous Inner Class for Java 7 compatibility
        startBtn.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                toggleServer(e);
            }
        });
        
        decryptBtn.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                // Decryption runs in a new thread to keep the GUI responsive
                new Thread(() -> decryptPendingFile()).start();
            }
        });
        
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setMinimumSize(new Dimension(500, 400));
        setLocationRelativeTo(null);
    }

    private void toggleServer(ActionEvent e) {
        if (!running) startServer();
        else stopServer();
    }

    private void startServer() {
        try {
            int port = Integer.parseInt(portField.getText().trim());
            rsaKeyPair = Crypto.generateRSAKeyPair(2048);
            serverSocket = new ServerSocket(port);
            running = true;
            startBtn.setText("Stop Server");
            statusField.setText("Server is listening");
            log("Server started on port " + port);
            // Using method reference here is acceptable since it's within a functional interface context
            pool.submit(this::acceptLoop); 
        } catch (Exception ex) {
            log("Failed to start server: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private void acceptLoop() {
        try {
            while (running) {
                Socket s = serverSocket.accept();
                log("Accepted connection: " + s.getRemoteSocketAddress());
                // Using lambda expression here is acceptable
                pool.submit(() -> handleClient(s));
            }
        } catch (IOException e) {
            if (running) log("Accept error: " + e.getMessage());
        }
    }

    private void handleClient(Socket socket) {
        // Only handle one file transfer at a time for manual decryption queueing
        if (pendingAesKey != null) {
            log("Error: Another file transfer is pending decryption. Ignoring new connection.");
            try { socket.close(); } catch (IOException ignored) {}
            return;
        }

        try (Socket s = socket;
             DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
             DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()))) {

            // 1. Send RSA public key
            byte[] pub = rsaKeyPair.getPublic().getEncoded();
            out.writeInt(pub.length);
            out.write(pub);
            out.flush();
            log("Sent RSA public key to client (" + pub.length + " bytes).");

            // 2. Receive and Decrypt AES key (RSA)
            int encKeyLen = in.readInt();
            byte[] encAesKey = new byte[encKeyLen];
            in.readFully(encAesKey);
            byte[] aesKeyBytes = Crypto.rsaDecrypt(encAesKey, rsaKeyPair.getPrivate());
            
            // Store the key and IV for later decryption
            pendingAesKey = Crypto.fromBytesToAESKey(aesKeyBytes);
            log("Received and decrypted AES session key.");
            System.out.println(encAesKey);
            System.out.print(pendingAesKey);
            // 3. Receive IV
            int ivLen = in.readInt();
            pendingIv = new byte[ivLen];
            in.readFully(pendingIv);

            // 4. Receive File Metadata
            int fnameLen = in.readInt();
            byte[] fnameB = new byte[fnameLen];
            in.readFully(fnameB);
            decryptedFileName = new String(fnameB, "UTF-8");

            long originalSize = in.readLong();
            pendingEncryptedSize = in.readLong();
            
            String tempEncryptedName = decryptedFileName + ".enc";
            encryptedFilePath = new File(saveDir, tempEncryptedName).getAbsolutePath();
            
            log(String.format("Receiving ENCRYPTED file '%s' (Original size: %d, Encrypted size: %d)", decryptedFileName, originalSize, pendingEncryptedSize));

            // 5. Read Encrypted Data and Save (WITHOUT decryption)
            File encFile = new File(encryptedFilePath);
            try (LimitedInputStream lim = new LimitedInputStream(in, pendingEncryptedSize);
                 FileOutputStream fos = new FileOutputStream(encFile)) {

                byte[] buf = new byte[8192];
                int r;
                long total = 0;
                while ((r = lim.read(buf)) != -1) {
                    fos.write(buf, 0, r);
                    total += r;
                }
                fos.flush();
                log("Encrypted file saved to: " + encryptedFilePath + " (" + total + " bytes)");
            }

            // Enable decryption action
            SwingUtilities.invokeLater(() -> {
                statusField.setText("Encrypted File Pending Decryption");
                decryptBtn.setEnabled(true);
            });

        } catch (Exception ex) {
            log("Client handler error: " + ex.getMessage());
            resetPendingState();
            ex.printStackTrace();
        }
    }

    private void decryptPendingFile() {
        if (pendingAesKey == null || encryptedFilePath == null) {
            log("Error: No pending file data or key to decrypt.");
            return;
        }

        File encryptedFile = new File(encryptedFilePath);
        File decryptedFile = new File(saveDir, "DECRYPTED_" + decryptedFileName); // Add prefix to differentiate
        
        SwingUtilities.invokeLater(() -> {
            decryptBtn.setEnabled(false);
            statusField.setText("Decrypting...");
        });
        log("Initiating decryption of " + encryptedFile.getName());

        try {
            Cipher decryptCipher = Crypto.createAESCipher(Cipher.DECRYPT_MODE, pendingAesKey, pendingIv);
            
            // Use the actual file size for streaming
            // long fileSize = encryptedFile.length(); // Not strictly needed for GCM stream

            try (FileInputStream fis = new FileInputStream(encryptedFile);
                 CipherInputStream cis = new CipherInputStream(fis, decryptCipher);
                 FileOutputStream fos = new FileOutputStream(decryptedFile)) {

                byte[] buf = new byte[8192];
                int r;
                long total = 0;
                while ((r = cis.read(buf)) != -1) {
                    fos.write(buf, 0, r);
                    total += r;
                }
                fos.flush();
                
                log("Decryption successful! Plaintext file saved to: " + decryptedFile.getAbsolutePath() + " (" + total + " bytes)");
                System.out.println(decryptCipher);
                // Clean up: delete the encrypted temporary file
                if (encryptedFile.delete()) {
                    log("Cleaned up temporary encrypted file.");
                }

                SwingUtilities.invokeLater(() -> statusField.setText("Decryption Complete"));

            } catch (Exception ex) {
                log("Decryption FAILED! (Integrity check failed or Stream error) Error: " + ex.getMessage());
                if (decryptedFile.exists()) decryptedFile.delete(); 
                SwingUtilities.invokeLater(() -> statusField.setText("Decryption Failed"));
            }

        } catch (Exception ex) {
            log("Error setting up decryption: " + ex.getMessage());
        } finally {
            resetPendingState();
        }
    }
    
    private void resetPendingState() {
        pendingAesKey = null;
        pendingIv = null;
        encryptedFilePath = null;
        decryptedFileName = null;
        pendingEncryptedSize = 0;
        SwingUtilities.invokeLater(() -> decryptBtn.setEnabled(false));
    }


    private void stopServer() {
        running = false;
        startBtn.setText("Start Server");
        statusField.setText("Stopped");
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException e) {
            log("Error closing server: " + e.getMessage());
        }
        log("Server stopped.");
        resetPendingState();
    }

    private void log(String s) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(s + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        System.out.println("[SERVER] " + s);
    }

    // InputStream wrapper to ensure we only read 'limit' bytes from underlying stream
    static class LimitedInputStream extends InputStream {
        private final DataInputStream in;
        private long remaining;
        public LimitedInputStream(DataInputStream in, long limit) { this.in = in; this.remaining = limit; }
        @Override public int read() throws IOException {
            if (remaining <= 0) return -1;
            int v = in.read();
            if (v != -1) remaining--;
            return v;
        }
        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) return -1;
            int toRead = (int)Math.min(len, remaining);
            int r = in.read(b, off, toRead);
            if (r > 0) remaining -= r;
            return r;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            server srv = new server();
            srv.setVisible(true);
        });
    }
}