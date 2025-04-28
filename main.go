package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func negotiate_connection(connection_name string) (*SymmetricEncryptedConn, error) {
	addr := net.UDPAddr{
		IP:   net.ParseIP("172.232.24.105"),
		Port: 2001,
	}
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return nil, err
	}
	socket, err := NewEncryptedServerConn(conn)
	local := ExtractUDPAddr(socket.LocalAddr())
	socket.WriteWithHeader([]byte(fmt.Sprintf("REGISTER,%s", connection_name)))
	for {
		buffer := make([]byte, 1024)
		n, _ := socket.Read(buffer)
		message := string(buffer[:n])
		fmt.Println(message)
		sections := strings.Split(message, ",")
		if sections[0] == "REGISTERED" {
			continue
		}
		if sections[0] == "SUCCESS" {
			socket.WriteWithHeader([]byte("CLOSE"))
			socket.Close()
			fmt.Println(sections[2])
			peer_port, err := strconv.Atoi(sections[2])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			addr := net.UDPAddr{
				IP:   net.ParseIP(sections[1]),
				Port: peer_port,
			}
			peer, err := net.DialUDP("udp", &local, &addr)
			if err != nil {
				fmt.Println(err)
			}
			leader := sections[3] == "LEADER"
			return handshake(peer, leader)
		}
	}
}

func main() {
	args := os.Args
	peer, err := negotiate_connection("hello_go")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if args[2] == "-i" {
		handle_peer(peer)
		os.Exit(0)
	}
	if args[2] == "-u" {
		msg_buf := make([]byte, 32)
		peer.Write([]byte("FILE"))
		var n = 0
		n, _ = peer.Read(msg_buf)
		reply := string(msg_buf[:n])
		fmt.Println(reply, len(reply))
		if reply != "ACK" {
			fmt.Println("Failure to confirm")
			os.Exit(1)
		}
		file, err := os.Open(args[3])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for err != io.EOF {
			buffer := make([]byte, 8192)
			n, err = file.Read(buffer)
			peer.Write(buffer[:n])
			b := make([]byte, 32)
			peer.Read(b)
		}
	}
	if args[2] == "-r" {
		msg_buf := make([]byte, 32)
		var n = 1
		var err error
		n, _ = peer.Read(msg_buf)
		msg := string(msg_buf[:n])
		if msg == "FILE" {
			peer.Write([]byte("ACK"))
		}
		file, err := os.OpenFile(args[3], os.O_CREATE, os.ModeAppend)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for n != 0 {
			buffer := make([]byte, 8192)
			peer.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err = peer.Read(buffer)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(n)
			peer.Write([]byte("ACK"))
			file.Write(buffer[:n])
		}
	}
}

func handshake(peer *net.UDPConn, leader bool) (*SymmetricEncryptedConn, error) {
	fmt.Printf("Entering handshake leader: %v\n", leader)
	attempts := 0
	for leader && attempts < 10 {
		buffer := make([]byte, 256)
		peer.Write([]byte("HELLO"))
		peer.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := peer.Read(buffer)
		if err == os.ErrDeadlineExceeded {
			attempts++
			continue
		}
		if err != nil {
			fmt.Println(err)
			attempts++
			continue
		}
		msg := string(buffer[:n])
		if msg == "ACK" {
			peer.SetReadDeadline(time.Time{})
			break
		}
	}
	for !leader {
		buffer := make([]byte, 256)
		n, err := peer.Read(buffer)
		if err != nil {
			fmt.Println(err)
			continue
		}
		msg := string(buffer[:n])
		if msg == "HELLO" {
			peer.Write([]byte("ACK"))
			break
		}
	}
	fmt.Println("Handshake complete starting encryption")
	priv_key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	public_pem := x509.MarshalPKCS1PublicKey(&priv_key.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(public_pem)
	buffer := make([]byte, 512)

	peer.Write([]byte(fmt.Sprintf("ENCRYPT,%s", encoded)))
	n, err := peer.Read(buffer)
	if err != nil {
		return nil, err
	}
	sections := strings.Split(string(buffer[:n]), ",")
	if sections[0] == "ENCRYPT" {
		pubkey_bytes, err := base64.StdEncoding.DecodeString(sections[1])
		if err != nil {
			return nil, err
		}
		pubkey, err := x509.ParsePKCS1PublicKey(pubkey_bytes)
		enc := EncryptedConn{
			privkey: priv_key,
			pubkey:  pubkey,
			conn:    peer,
		}
		if leader {
			symkey := make([]byte, 32)
			io.ReadFull(rand.Reader, symkey)
			enc.Write(symkey)
			block, err := aes.NewCipher(symkey)
			if err != nil {
				return nil, err
			}
			return &SymmetricEncryptedConn{
				block: block,
				conn: peer,
				key: symkey,
			}, nil
		} else {
			symkey := make([]byte, 32)
			enc.Read(symkey)
			block, err := aes.NewCipher(symkey)
			if err != nil {
				return nil, err
			}
			return &SymmetricEncryptedConn{
				block: block,
				conn: peer,
				key: symkey,
			}, nil
		}
	}
	return nil, fmt.Errorf("Incorrect command")
}

func handle_peer(peer *SymmetricEncryptedConn) {
	input := bufio.NewReader(os.Stdin)
	go (func() {
		for {
			buffer := make([]byte, 1024)
			n, err := peer.Read(buffer)
			if err != nil {
				fmt.Println(err)
				fmt.Println(n)
			}
			fmt.Println(string(buffer))
		}
	})()
	for {
		line, _, _ := input.ReadLine()
		peer.Write([]byte(line))
	}
}
