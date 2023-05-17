package main

import (
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
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

var cache = make(map[string]ServerResponse)
var publicKeys = make(map[string]*rsa.PublicKey)

const (
	CONN_HOST = "localhost"
	CONN_PORT = "3333"
	CONN_TYPE = "tcp"
)

var fileServerURLs = []string{
	"http://localhost:8081/",
	"http://localhost:8082/",
	"http://localhost:8083/",
}

var currentFileServerIndex = 0

type ClientRequest struct {
	FileName  string
	PublicKey []byte
}

type ServerResponse struct {
	AESKey        []byte
	EncryptedFile []byte
	FileHash      []byte
}

func main() {
	// Read the server's certificate and private key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
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
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
	}

	// Create a TLS listener
	l, err := tls.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	defer l.Close()

	log.Println("Proxy server is up and running on " + CONN_HOST + ":" + CONN_PORT)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()

	var req ClientRequest
	dec := gob.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		log.Println("Error decoding client request:", err)
		return
	}

	clientPublicKey, err := loadPublicKey(req.PublicKey)
	if err != nil {
		log.Println("Error loading client public key:", err)
		return
	}

	publicKeys[req.FileName] = clientPublicKey

	if resp, ok := cache[req.FileName]; ok {
		log.Println("Cache hit for", req.FileName)

		encryptedAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, clientPublicKey, resp.AESKey)
		if err != nil {
			log.Println("Error encrypting AES key:", err)
			return
		}

		respWithEncryptedAESKey := ServerResponse{
			AESKey:        encryptedAESKey,
			EncryptedFile: resp.EncryptedFile,
			FileHash:      resp.FileHash,
		}

		sendResponse(conn, respWithEncryptedAESKey)
		return
	}

	url := getNextFileServerURL() + req.FileName
	log.Println("Making GET request to", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Error making GET request to file server: %v", err)
		return
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return
	}

	// Compute the hash with SHA256
	hash := sha256.Sum256(data)

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		log.Println("Error generating AES key:", err)
		return
	}

	encryptedAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, clientPublicKey, aesKey)
	if err != nil {
		log.Println("Error encrypting AES key:", err)
		return
	}

	c, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Println("Error creating AES cipher:", err)
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("Error creating GCM:", err)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println("Error generating nonce:", err)
		return
	}

	encryptedFile := gcm.Seal(nonce, nonce, data, nil)

	serverResp := ServerResponse{
		AESKey:        aesKey,
		EncryptedFile: encryptedFile,
		FileHash:      hash[:],
	}

	respWithEncryptedAESKey := ServerResponse{
		AESKey:        encryptedAESKey,
		EncryptedFile: encryptedFile,
		FileHash:      hash[:],
	}

	cache[req.FileName] = serverResp
	sendResponse(conn, respWithEncryptedAESKey)
}

func loadPublicKey(publicKeyBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: " + err.Error())
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unknown type of public key")
	}
}

func sendResponse(conn net.Conn, resp ServerResponse) {
	enc := gob.NewEncoder(conn)
	if err := enc.Encode(resp); err != nil {
		log.Println("Error encoding server response:", err)
	}
}

func getNextFileServerURL() string {
	url := fileServerURLs[currentFileServerIndex]
	currentFileServerIndex = (currentFileServerIndex + 1) % len(fileServerURLs)
	return url
}
