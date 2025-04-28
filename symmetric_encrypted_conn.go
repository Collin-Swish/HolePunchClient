package udpconn

import (
	"crypto/cipher"
	"encoding/binary"
	"net"
)

type SymmetricEncryptedConn struct {
	block cipher.Block
	conn  *net.UDPConn
	key   []byte
}

func (self *SymmetricEncryptedConn) Write(b []byte) (int, error) {
	l := len(b)
	padded_len := 16-(l%16)
	src_buffer := make([]byte, l+padded_len)
	copy(src_buffer, b)
	buffer := make([]byte, l+padded_len+4)
	binary.LittleEndian.PutUint32(buffer[0:4], uint32(l))
	for i := 0; i < len(src_buffer); i += 16 {
		self.block.Encrypt(buffer[i+4:], src_buffer[i:])
	}
	return self.conn.Write(buffer)
}

func (self *SymmetricEncryptedConn) Read(b []byte) (int, error) {
	l := len(b)
	buffer := make([]byte, l+(16-(l%16))+4)
	tmp_buffer := make([]byte, l+(16-(l%16)))
	_, err := self.conn.Read(buffer)
	if err != nil {
		return 0, err
	}
	olen := int(binary.LittleEndian.Uint32(buffer[0:4]))
	for i := 0; i < len(tmp_buffer); i += 16 {
		self.block.Decrypt(tmp_buffer[i:], buffer[i+4:])
	}
	copy(b, tmp_buffer[:olen])
	return olen, nil
}