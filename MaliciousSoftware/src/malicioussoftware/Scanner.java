/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package malicioussoftware;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HashSet;

public class Scanner {

    // A set to store malware signatures loaded from the signature file
    private HashSet<MalwareSignature> signatures = new HashSet<>();

    // Constructor that initializes the Scanner with malware signatures from a given file path
    public Scanner(String signatureFilePath) throws IOException {
        // Create a BufferedReader to read the signature file line by line
        BufferedReader br = new BufferedReader(new FileReader(signatureFilePath));
        String line;

        // Read each line from the signature file
        while ((line = br.readLine()) != null) {
            // Split the line into parts: hash and signature name
            String[] parts = line.split(" ");
            // Add the malware signature to the HashSet
            signatures.add(new MalwareSignature(parts[1], parts[0]));
        }
        // Close the BufferedReader to release resources
        br.close();
    }

    // Method to scan files in the specified directory for malware signatures
    public HashSet<DetectedMalware> scan(String path, boolean includeSubFolders) throws Exception {
        // A set to store detected malware files
        HashSet<DetectedMalware> detectedMalwares = new HashSet<>();

        // Walk through the file tree starting from the specified path
        Files.walk(Paths.get(path))
                // Filter for regular files (not directories)
                .filter(Files::isRegularFile)
                // For each file found, perform the following
                .forEach(file -> {
                    try {
                        // Calculate the MD5 checksum of the file
                        String checksum = MalwareSignature.checksum(MessageDigest.getInstance("MD5"), file.toFile());
                        // Check the checksum against each malware signature
                        for (MalwareSignature signature : signatures) {
                            // If a matching signature is found, create a DetectedMalware object
                            if (signature.getHash().equals(checksum)) {
                                detectedMalwares.add(new DetectedMalware(file.toString(), file.getFileName().toString(), signature, checksum));
                            }
                        }
                    } catch (Exception e) {
                        // Print stack trace if an exception occurs during scanning
                        e.printStackTrace();
                    }
                });

        // Return the set of detected malware files
        return detectedMalwares;
    }
}
