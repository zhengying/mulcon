package main

import (
	"fmt"
	"log"
	"net"
)

const (
	defaultMethod   = "chacha20"
	defaultPassword = "123456"
)

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	raddr, err := net.ResolveUDPAddr("udp4", ":7878")
	fatalErr(err)
	rconn, err := net.ListenUDP("udp4", raddr)
	fatalErr(err)
	fmt.Println(rconn.LocalAddr(), rconn.RemoteAddr())
	dialer := func() (conn net.Conn, err error) {
		conn, err = net.DialUDP("udp4", nil, raddr)
		return
	}
	listener, err := Listen(rconn, defaultMethod, defaultPassword)
	fatalErr(err)
	go func() {
		conn, err := Dial(dialer, 1000, defaultMethod, defaultPassword)
		fatalErr(err)
		// t := time.NewTicker(time.Microsecond)
		go func() {
			buf := make([]byte, 4096)
			var count int
			// go func() {
			// 	t := time.NewTicker(time.Second)
			// 	for _ = range t.C {
			// 		log.Println(count)
			// 	}
			// }()
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				if n > 0 {
					// log.Println(n)
					count += n
				}
			}
		}()
		buf := make([]byte, 1200)
		for {
			conn.Write(buf)
		}
	}()
	b := make([]byte, 4096)
	for {
		n, addr, err := listener.ReadFrom(b)
		// log.Println(n, addr, err)
		if n > 0 {
			// log.Println(string(b[:n]))
			listener.WriteTo(b[:n], addr)
		}
		if err != nil {
			return
		}
	}
	return
}

func fatalErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
