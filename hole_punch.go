package HolePunchClient

import (
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

func NegotiateConnection(connection_name string, server_ip string) (*SymmetricEncryptedConn, error) {
	addr := net.UDPAddr{
		IP:   net.ParseIP(server_ip),
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
			return Handshake(peer, leader)
		}
	}
}

func Handshake(peer *net.UDPConn, leader bool) (*SymmetricEncryptedConn, error) {
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
	// fmt.Println("Handshake complete starting encryption")
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
			Privkey: priv_key,
			Pubkey:  pubkey,
			Conn:    peer,
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
				Block: block,
				Conn: peer,
				Key: symkey,
			}, nil
		} else {
			symkey := make([]byte, 32)
			enc.Read(symkey)
			block, err := aes.NewCipher(symkey)
			if err != nil {
				return nil, err
			}
			return &SymmetricEncryptedConn{
				Block: block,
				Conn: peer,
				Key: symkey,
			}, nil
		}
	}
	return nil, fmt.Errorf("Incorrect command")
}

