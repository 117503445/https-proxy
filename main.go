package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

const (
	username = "your_username"
	password = "your_password"
)

func handleHTTPSConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 读取客户端发送的 CONNECT 请求
	buffer := make([]byte, 4096)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Println("Error reading CONNECT request:", err)
		return
	}

	// 解析请求行和头部
	request := string(buffer[:n])
	lines := strings.Split(request, "\r\n")
	if len(lines) < 1 {
		log.Println("Invalid request")
		return
	}

	requestLine := lines[0]
	var host string
	_, err = fmt.Sscanf(requestLine, "CONNECT %s HTTP/1.1", &host)
	if err != nil {
		log.Println("Error parsing CONNECT request:", err)
		return
	}

	// 验证 Proxy-Authorization 头部
	authHeader := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "Proxy-Authorization:") {
			authHeader = strings.TrimSpace(line[len("Proxy-Authorization:"):])
			break
		}
	}

	if !isValidAuth(authHeader) {
		clientConn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Access to the proxy\"\r\n\r\n"))
		log.Println("Invalid Proxy-Authorization header")
		return
	}

	// 向客户端发送 200 OK 响应
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Println("Error writing 200 OK response:", err)
		return
	}

	// 连接到目标服务器
	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Println("Error connecting to target server:", err)
		return
	}
	defer serverConn.Close()

	// 使用 goroutine 进行双向数据转发
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(serverConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, serverConn)
	}()

	wg.Wait()
}

func isValidAuth(authHeader string) bool {
	if !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}

	encodedCredentials := strings.TrimPrefix(authHeader, "Basic ")
	decodedCredentials, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return false
	}

	credentials := string(decodedCredentials)
	expectedCredentials := fmt.Sprintf("%s:%s", username, password)
	return credentials == expectedCredentials
}

func main() {
	// 创建一个自签名的 TLS 证书
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal("Error loading X509 key pair:", err)
	}

	// 配置 TLS
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	// 创建一个监听器
	listener, err := tls.Listen("tcp", ":20001", tlsConfig)
	if err != nil {
		log.Fatal("Error creating listener:", err)
	}
	defer listener.Close()

	log.Println("HTTPS proxy server is running on port 20001")

	for {
		// 接受客户端连接
		clientConn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		// 处理客户端连接
		go handleHTTPSConnection(clientConn)
	}
}
