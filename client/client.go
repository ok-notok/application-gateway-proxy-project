package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const (
	CONN_HOST = "localhost"
	CONN_PORT = "3333"
	CONN_TYPE = "tcp"
)

type ClientRequest struct {
	FileName  string
	PublicKey []byte
}

type ServerResponse struct {
	AESKey        []byte
	EncryptedFile []byte
	FileHash      []byte
}

type Client struct {
	privateKey *rsa.PrivateKey
}

func (c *Client) DecryptAESKey(encryptedAESKey []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, encryptedAESKey)
}

func main() {
	// Load the client's certificate and private key
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatal(err)
	}

	// Create a certificate pool
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Set up the TLS config
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	// Generate RSA key pair
	privateKey, publicKeyBytes, err := generateKeyPair()
	if err != nil {
		log.Fatal("Error generating RSA key pair:", err)
	}

	client := &Client{privateKey: privateKey}

	// Ask for user input on which file to download
	var fileName string
	fmt.Println("Enter the name of the file to get (file1 to file5):")
	fmt.Scanln(&fileName)

	// Connect to the server
	conn, err := tls.Dial(CONN_TYPE, CONN_HOST+":"+CONN_PORT, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Send request with public key
	req := ClientRequest{
		FileName:  fileName,
		PublicKey: publicKeyBytes,
	}

	enc := gob.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		log.Fatal("Error encoding client request:", err)
	}

	// Receive response
	var resp ServerResponse
	dec := gob.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		log.Fatal("Error decoding server response:", err)
	}

	// Decrypt AES key
	aesKey, err := client.DecryptAESKey(resp.AESKey)
	if err != nil {
		log.Fatal("Error decrypting AES key:", err)
	}

	// Decrypt the file
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal("Error creating AES cipher:", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal("Error creating GCM:", err)
	}

	nonceSize := gcm.NonceSize()
	if len(resp.EncryptedFile) < nonceSize {
		log.Fatal("Error: encrypted file too small")
	}

	nonce, ciphertext := resp.EncryptedFile[:nonceSize], resp.EncryptedFile[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal("Error decrypting file:", err)
	}

	// Compute the hash of the decrypted file data
	hash := sha256.Sum256(plaintext)

	// Check the hash against the one received from the server
	if !bytes.Equal(hash[:], resp.FileHash) {
		log.Fatal("File integrity check failed: the computed hash of the received file does not match the hash received from the server.")
	}

	// Write to a file
	f, err := os.Create("decrypted_" + fileName) // replace with actual file name
	if err != nil {
		log.Fatal("Error creating file:", err)
	}
	defer f.Close()

	if _, err := f.Write(plaintext); err != nil {
		log.Fatal("Error writing to file:", err)
	}

}

func generateKeyPair() (*rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}

	publicKeyBytes := pem.EncodeToMemory(&publicKeyBlock)

	return privateKey, publicKeyBytes, nil
}
