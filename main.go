package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/117503445/goutils"
	"github.com/alecthomas/kong"
	kongtoml "github.com/alecthomas/kong-toml"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/proxy"
)

type OutBound interface {
	ServerConn(host string) (net.Conn, error)
}

var outBound OutBound

type DirectOutBound struct {
}

func (d *DirectOutBound) ServerConn(host string) (net.Conn, error) {
	return net.Dial("tcp", host)
}

type HTTPOutBound struct {
	OutBound *url.URL
}

func NewHTTPOutBound(outbound string) *HTTPOutBound {
	url, err := url.Parse(outbound)
	if err != nil {
		log.Fatal().Err(err).Msg("Error parsing URL")
	}

	return &HTTPOutBound{
		OutBound: url,
	}
}

func (h *HTTPOutBound) ServerConn(host string) (net.Conn, error) {
	conn, err := net.Dial("tcp", h.OutBound.Host)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: host},
		Host:   host,
		Header: make(http.Header),
	}

	if h.OutBound.User != nil {
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(h.OutBound.User.String()))
		req.Header.Set("Proxy-Authorization", auth)
	}

	err = req.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy error: %s", resp.Status)
	}

	return conn, nil
}

type Socks5OutBound struct {
	OutBound *url.URL
}

func NewSocks5OutBound(outbound string) *Socks5OutBound {
	url, err := url.Parse(outbound)
	if err != nil {
		log.Fatal().Err(err).Msg("Error parsing URL")
	}

	return &Socks5OutBound{
		OutBound: url,
	}
}

func (s *Socks5OutBound) ServerConn(host string) (net.Conn, error) {
	var auth *proxy.Auth
	if s.OutBound.User != nil {
		password, exists := s.OutBound.User.Password()
		if !exists {
			return nil, fmt.Errorf("password not provided")
		}
		auth = &proxy.Auth{User: s.OutBound.User.Username(), Password: password}
	}
	dialer, err := proxy.SOCKS5("tcp", s.OutBound.Host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func NewOutBound(outBound string) OutBound {
	if strings.HasPrefix(outBound, "http://") {
		log.Info().Str("outbound", outBound).Msg("Use http outbound")
		return NewHTTPOutBound(outBound)
	} else if strings.HasPrefix(outBound, "socks5://") {
		log.Info().Str("outbound", outBound).Msg("Use socks5 outbound")
		return NewSocks5OutBound(outBound)
	} else {
		log.Info().Str("outbound", outBound).Msg("Use direct outbound")
		return &DirectOutBound{}
	}
}

var (
	username = ""
	password = ""
)

func handleHTTPSConnection(clientConn net.Conn) {
	log.Debug().Str("remoteAddr", clientConn.RemoteAddr().String()).Msg("New connection")
	defer clientConn.Close()

	buffer := make([]byte, 4096)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Warn().Err(err).Msg("Error reading CONNECT request")
		return
	}

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

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Warn().Err(err).Msg("Error writing 200 OK response")
		return
	}

	// serverConn, err := net.Dial("tcp", host)
	// if err != nil {
	// 	log.Warn().Err(err).Str("host", host).Msg("Error connecting to target server")
	// 	return
	// }
	// defer serverConn.Close()
	serverConn, err := outBound.ServerConn(host)
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
		if _, err := io.Copy(serverConn, clientConn); err != nil {
			log.Warn().Err(err).Msg("Error copying data")
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(clientConn, serverConn); err != nil {
			log.Warn().Err(err).Msg("Error copying data")
		}
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

	Outbound string `help:"OutBound address. empty for direct, http://host:port for http, socks5://host:port for socks5" default:"" env:"OUTBOUND"`
}

func main() {
	goutils.InitZeroLog()

	kong.Parse(&cli)
	kong.Parse(&cli, kong.Configuration(kongtoml.Loader, cli.Config...))

	log.Info().Str("cert", cli.Cert).Str("key", cli.Key).Int("port", cli.Port).Str("username", cli.Username).Strs("config", cli.Config).Str("outbound", cli.Outbound).Msg("Load Config")

	if cli.Username == "" && cli.Password == "" {
		log.Info().Msg("No username and password provided, disabling authentication")
	} else if cli.Username != "" && cli.Password != "" {
		log.Info().Msg("Using provided username and password for authentication")
		username = cli.Username
		password = cli.Password
	} else {
		log.Fatal().Msg("Both username and password must be provided")
	}

	outBound = NewOutBound(cli.Outbound)

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
