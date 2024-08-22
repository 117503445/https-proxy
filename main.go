package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/117503445/goutils"
	"github.com/rs/zerolog/log"

	"github.com/alecthomas/kong"
	kongtoml "github.com/alecthomas/kong-toml"
)

var (
	username = ""
	password = ""
)

func handleHTTPSConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 读取客户端发送的 CONNECT 请求
	buffer := make([]byte, 4096)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Warn().Err(err).Msg("Error reading CONNECT request")
		return
	}

	// 解析请求行和头部
	request := string(buffer[:n])
	lines := strings.Split(request, "\r\n")
	if len(lines) < 1 {
		log.Warn().Msg("Invalid request")
		return
	}

	requestLine := lines[0]
	var host string
	_, err = fmt.Sscanf(requestLine, "CONNECT %s HTTP/1.1", &host)
	if err != nil {
		log.Warn().Err(err).Str("requestLine", requestLine).Msg("Error parsing request line")
		return
	}

	if username != "" {
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
			log.Warn().Msg("Invalid Proxy-Authorization header")
			return
		}
	}

	// 向客户端发送 200 OK 响应
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Warn().Err(err).Msg("Error writing 200 OK response")
		return
	}

	// 连接到目标服务器
	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Warn().Err(err).Str("host", host).Msg("Error connecting to target server")
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

var cli struct {
	Config []string `short:"c" help:"Config files." type:"path" default:"config.toml" env:"CONFIG"`

	Cert     string `help:"Path to the certificate." type:"path" required:"true" default:"server.crt" env:"CERT"`
	Key      string `help:"Path to the private key." type:"path" required:"true" default:"server.key" env:"KEY"`
	Port     int    `help:"Port to listen on." default:"443" env:"PORT"`
	Username string `help:"Username for proxy authentication." env:"USERNAME"`
	Password string `help:"Password for proxy authentication." env:"PASSWORD"`
}

func main() {
	goutils.InitZeroLog()

	kong.Parse(&cli)
	kong.Parse(&cli, kong.Configuration(kongtoml.Loader, cli.Config...))

	log.Info().Str("cert", cli.Cert).Str("key", cli.Key).Int("port", cli.Port).Str("username", cli.Username).Strs("config", cli.Config).Msg("Load Config")

	if cli.Username == "" && cli.Password == "" {
		log.Info().Msg("No username and password provided, disabling authentication")
	} else if cli.Username != "" && cli.Password != "" {
		log.Info().Msg("Using provided username and password for authentication")
	} else {
		log.Fatal().Msg("Both username and password must be provided")
	}

	cert, err := tls.LoadX509KeyPair(cli.Cert, cli.Key)
	if err != nil {
		log.Fatal().Err(err).Msg("Error loading X509 key pair")
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", cli.Port), tlsConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating listener")
	}
	defer listener.Close()

	log.Info().Int("port", cli.Port).Msg("HTTPS proxy server is running")

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Warn().Err(err).Msg("Error accepting connection")
			continue
		}

		go handleHTTPSConnection(clientConn)
	}
}
