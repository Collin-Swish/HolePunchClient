package HolePunchClient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type EncryptedConn struct {
	Privkey *rsa.PrivateKey
	Pubkey  *rsa.PublicKey
	Conn    *net.UDPConn
}

func PrefixBuffer(buffer []byte) []byte {
	new_buffer := make([]byte, len(buffer)+1)
	new_buffer[0] = 255
	copy(new_buffer[1:], buffer)
	return new_buffer
}

func NewEncryptedServerConn(conn *net.UDPConn) (*EncryptedConn, error) {
	buffer := make([]byte, 1024)
	priv_key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	public_pem := x509.MarshalPKCS1PublicKey(&priv_key.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(public_pem)
	_, err = conn.Write([]byte(fmt.Sprintf("ENCRYPT,%s", encoded)))
	if err != nil {
		return nil, err
	}
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	sections := strings.Split(string(buffer[:n]), ",")
	server_public_pem, err := base64.StdEncoding.DecodeString(sections[1])
	if err != nil {
		return nil, err
	}
	server_public_key, err := x509.ParsePKCS1PublicKey(server_public_pem)
	if err != nil {
		return nil, err
	}
	result := EncryptedConn{
		Privkey: priv_key,
		Pubkey:  server_public_key,
		Conn:    conn,
	}
	return &result, nil
}

func (self *EncryptedConn) LocalAddr() net.Addr {
	return self.Conn.LocalAddr()
}

func (self *EncryptedConn) Close() error {
	return self.Conn.Close()
}

func (self *EncryptedConn) Write(b []byte) (int, error) {
	encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, self.Pubkey, b, nil)
	fmt.Println(self.Pubkey.Size())
	if err != nil {
		return 0, err
	}
	return self.Conn.Write(encrypted)
}

func (self *EncryptedConn) WriteWithHeader(b []byte) (int, error) {
	encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, self.Pubkey, b, nil)
	if err != nil {
		return 0, err
	}
	return self.Conn.Write(PrefixBuffer(encrypted))
}

func (self *EncryptedConn) Read(b []byte) (int, error) {
	buffer := make([]byte, 2048)
	n, err := self.Conn.Read(buffer)
	if err != nil {
		return n, err
	}
	buffer = buffer[:n]
	decrypted, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, self.Privkey, buffer, nil)
	copy(b, decrypted)
	return len(decrypted), nil
}

func ExtractUDPAddr(local_addr net.Addr) net.UDPAddr {
	strs := strings.Split(local_addr.String(), ":")
	port, err := strconv.Atoi(strs[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return net.UDPAddr{
		IP:   net.ParseIP(strs[0]),
		Port: port,
	}
}

func WriteEncrypted(buffer []byte, socket *net.UDPConn, pkey *rsa.PublicKey) (int, error) {
	data, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pkey, buffer, nil)
	if err != nil {
		return 0, nil
	}
	return socket.Write(data)
}
