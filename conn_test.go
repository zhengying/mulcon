package mulcon

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
)

const (
	laddr = "127.0.0.1:6666"
)

func dialUdp(raddr string) (conn *net.UDPConn, err error) {
	udpaddr, err := net.ResolveUDPAddr("udp4", raddr)
	if err != nil {
		return
	}
	conn, err = net.DialUDP("udp4", nil, udpaddr)
	return
}

func dialMul(raddr string) (conn *Local, err error) {
	dialer := func() (conn net.Conn, err error) {
		conn, err = dialUdp(raddr)
		return
	}
	conn, err = Dial(dialer, 10, "chacha20", "123")
	return
}

func listenUdp(laddr string) (conn *net.UDPConn, err error) {
	udpaddr, err := net.ResolveUDPAddr("udp4", laddr)
	if err != nil {
		return
	}
	conn, err = net.ListenUDP("udp4", udpaddr)
	return
}

func listenMul(laddr string) (conn *Server, err error) {
	c, err := listenUdp(laddr)
	if err != nil {
		return
	}
	conn, err = Listen(c, "chacha20", "123")
	return
}

func TestDialUdp(t *testing.T) {
	conn, err := dialUdp(laddr)
	if err != nil {
		t.Error(errors.Wrap(err, "TestDialUdp"))
	}
	defer conn.Close()
	return
}

func TestListenUdp(t *testing.T) {
	conn, err := listenUdp(laddr)
	if err != nil {
		t.Error(errors.Wrap(err, "TestListenUdp"))
	}
	defer conn.Close()
	return
}

func TestDialMul(t *testing.T) {
	conn, err := dialMul(laddr)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()
	return
}

func TestListenMul(t *testing.T) {
	conn, err := listenMul(laddr)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()
	return
}

func TestSingleReadAndWrite(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	listener, err := listenMul(laddr)
	if err != nil {
		t.Error(err)
	}
	defer listener.Close()

	conn, err := dialMul(laddr)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	localaddr := conn.LocalAddr().String()
	buf := make([]byte, 1000)
	rbuf := make([]byte, 2000)
	for i := 0; i < 1000; i++ {
		binary.Read(rand.Reader, binary.BigEndian, buf)
		n, err := conn.Write(buf)
		if err != nil {
			t.Error(err)
		}
		if n != len(buf) {
			t.Error(fmt.Errorf("short write! n = %v but except %d", n, len(buf)))
		}
		n, addr, err := listener.ReadFrom(rbuf)
		if err != nil {
			t.Error(err)
		}
		if n != len(buf) {
			t.Error(fmt.Errorf("unexpected n = %d", n))
		}
		if addr.String() != localaddr {
			t.Error(fmt.Errorf("unexpected addr = %s, expect %s", addr.String(), localaddr))
		}
		if reflect.DeepEqual(buf, rbuf[:n]) == false {
			t.Error(fmt.Errorf("broken data"))
		}
	}
	return
}

func TestMultipleWriterAndReader(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	listener, err := listenMul(laddr)
	if err != nil {
		t.Error(err)
	}
	defer listener.Close()

	nwrite := 100
	nwriter := 10

	f := func() {
		conn, err := dialMul(laddr)
		if err != nil {
			t.Error(err)
		}
		defer conn.Close()

		buf := make([]byte, 1000)
		for i := 0; i < nwrite; i++ {
			// binary.Read(rand.Reader, binary.BigEndian, buf)
			time.Sleep(time.Millisecond * 10)
			n, err := conn.Write(buf)
			if err != nil {
				return
			}
			if n != len(buf) {
				t.Error(fmt.Errorf("short write! n = %v but except %d", n, len(buf)))
			}
		}
	}

	for i := 0; i < nwriter; i++ {
		go f()
	}

	buf := make([]byte, 2000)
	for i := 0; i < nwrite*nwriter/2; i++ {
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			t.Error(err)
		}
		if n != 1000 {
			t.Error(fmt.Errorf("unexpected n = %d", n))
		}
	}
}

func TestEchoClientAndServer(t *testing.T) {
	echoServerAddr := "127.0.0.1:5555"
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	listener, err := listenMul(echoServerAddr)
	if err != nil {
		t.Error(err)
	}
	defer listener.Close()

	conn, err := dialMul(echoServerAddr)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 2048)
		defer conn.Close()
		for {
			n, addr, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			_, err = listener.WriteTo(buf[:n], addr)
			if err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 1400)
	rbuf := make([]byte, 1400)
	for i := 0; i < 1000; i++ {
		binary.Read(rand.Reader, binary.BigEndian, buf)
		n, err := conn.Write(buf)
		if n != len(buf) {
			t.Error(fmt.Errorf("short write! n = %d", n))
		}
		if err != nil {
			t.Error(err)
		}
		n, err = conn.Read(rbuf)
		if n != len(buf) {
			t.Error(fmt.Errorf("unexpected n = %d", n))
		}
		if err != nil {
			t.Error(err)
		}
		if reflect.DeepEqual(buf, rbuf) == false {
			t.Error("broken data")
			log.Println(buf)
			log.Println(rbuf)
		}
	}
}
func TestConn(t *testing.T) {
	return
}
