package mulcon

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ccsexyz/utils"
)

// packet
// <pkt-type 1byte> <noplen 1byte> <pkt-len 2byte> <nop-data nbyte> <payload mbyte>

const (
	rep    = iota
	syn    = iota
	synack = iota
	ack    = iota

	destroyed    = iota
	created      = iota
	synsent      = iota
	repsent      = iota
	synrecv      = iota
	synackrecv   = iota
	ackrecv      = iota
	pshrecv      = iota
	establishing = iota
	established  = iota

	pkthdrlen        = 4
	sessionKeyLength = 16
)

type Dialer func() (net.Conn, error)

type pkt struct {
	pktype int
	noplen int
	pktlen int
}

func decodePkt(b []byte) *pkt {
	return &pkt{
		pktlen: int(binary.BigEndian.Uint16(b[2:])),
		pktype: int(b[0]),
		noplen: int(b[1]),
	}
}

func (p *pkt) valid(b []byte) bool {
	switch p.pktype {
	case rep, syn, synack, ack:
	default:
		return false
	}
	if len(b) != p.pktlen+p.noplen {
		return false
	}
	return true
}

func (p *pkt) encode(b []byte) {
	binary.BigEndian.PutUint16(b[2:], uint16(p.pktlen))
	b[1] = byte(p.noplen)
	b[0] = byte(p.pktype)
}

type cipher struct {
	method   string
	password string
	ivlen    int
}

func (c *cipher) getIvlen() int {
	if c.ivlen == 0 {
		c.ivlen = utils.GetIvLen(c.method)
	}
	return c.ivlen
}

func (c *cipher) decrypt(b []byte) (d []byte, dec utils.Decrypter, err error) {
	if c.ivlen == 0 {
		c.ivlen = utils.GetIvLen(c.method)
	}
	if len(b) < c.ivlen {
		err = fmt.Errorf("data is too short")
		return
	}
	dec, err = utils.NewDecrypter(c.method, c.password, b[:c.ivlen])
	if err != nil {
		return
	}
	b = b[c.ivlen:]
	dec.Decrypt(b, b)
	d = b
	return
}

func (c *cipher) encrypt(b []byte) (enc utils.Encrypter, err error) {
	if c.ivlen == 0 {
		c.ivlen = utils.GetIvLen(c.method)
	}
	if len(b) < c.ivlen {
		err = fmt.Errorf("data is too short")
		return
	}
	enc, err = utils.NewEncrypter(c.method, c.password)
	if err != nil {
		return
	}
	copy(b, enc.GetIV())
	enc.Encrypt(b[c.ivlen:], b[c.ivlen:])
	return
}

type Local struct {
	*cipher
	laddr         net.Addr
	raddr         net.Addr
	die           chan bool
	readch        chan []byte
	lock          sync.RWMutex
	localSessions []*localSession
	ts            time.Time
	rr            int32
	keystr        string
	rtimer        *time.Timer
	wtimer        *time.Timer
	dialer        Dialer
}

type localSession struct {
	net.Conn
	*cipher
	lock      sync.RWMutex
	die       chan bool
	local     *Local
	ts        time.Time
	starttime time.Time
	state     int
}

func Dial(dialer Dialer, n int, method string, password string) (local *Local, err error) {
	conn, err := dialer()
	if err != nil {
		return
	}
	local = &Local{
		die:    make(chan bool),
		readch: make(chan []byte),
		cipher: &cipher{
			method:   method,
			password: password,
			ivlen:    utils.GetIvLen(method),
		},
		dialer: dialer,
		laddr:  conn.LocalAddr(),
		raddr:  conn.RemoteAddr(),
	}
	if n <= 0 {
		n = 1
	}
	for i := 0; i < n; i++ {
		local.localSessions = append(local.localSessions, local.newLocalSession())
	}
	sess := local.localSessions[0]
	sess.Conn = conn
	sess.state = synsent
	go sess.readLoop()
	return
}

func (l *Local) newLocalSession() *localSession {
	return &localSession{
		cipher: l.cipher,
		die:    make(chan bool),
		local:  l,
		state:  destroyed,
	}
}

func (l *localSession) Close() (err error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	select {
	case <-l.die:
	default:
		close(l.die)
	}
	if l.Conn != nil {
		err = l.Conn.Close()
	}
	return
}

func (l *Local) LocalAddr() net.Addr {
	return l.laddr
}

func (l *Local) RemoteAddr() net.Addr {
	return l.raddr
}

func (l *Local) Close() (err error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	select {
	case <-l.die:
	default:
		close(l.die)
	}
	for _, v := range l.localSessions {
		v.Close()
	}
	return
}

func (l *localSession) dorecv(b []byte) (err error) {
	select {
	case <-l.die:
	case <-l.local.die:
		err = fmt.Errorf("closed connection")
	case l.local.readch <- b:
	}
	return
}

func (l *localSession) readOnce() (err error) {
	b := make([]byte, 2048)
	n, err := l.Conn.Read(b)
	// log.Println(n)
	if err != nil {
		return
	}
	b = b[:n]
	if l.state == established {
		err = l.dorecv(b)
		return
	}
	p, nop, payload, err := l.tryDecodePkt(b)
	if err != nil {
		if l.state == synackrecv {
			l.starttime = time.Now()
			l.state = establishing
			// log.Println("enter establishing state")
		} else if l.state == establishing {
			if time.Now().Sub(l.starttime) > time.Second*30 {
				l.state = established
				// log.Println("enter established state")
			}
		} else {
			return
		}
		err = l.dorecv(b)
		return
	}
	// log.Println(p.pktype)
	if p.pktype == synack && (l.state == synsent || l.state == repsent) {
		l.state = synackrecv
		// log.Println("enter synackrecv state")
		if len(nop) != 0 {
			l.local.lock.RLock()
			if len(l.local.keystr) == 0 {
				l.local.keystr = string(nop)
				// log.Println("get key str")
			}
			l.local.lock.RUnlock()
		}
	}
	err = l.dorecv(payload)
	return
}

func (l *localSession) readLoop() {
	defer l.Close()
	for {
		err := l.readOnce()
		if err != nil {
			return
		}
	}
}

func (l *Local) Read(b []byte) (n int, err error) {
	select {
	case <-l.die:
		err = fmt.Errorf("read from closed connection")
	case buf := <-l.readch:
		n = copy(b, buf)
	}
	return
}

func (l *Local) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = l.Read(b)
	addr = l.raddr
	return
}

func (l *Local) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return l.Write(b)
}

func (l *localSession) Write(b []byte) (n int, err error) {
	// log.Println(l.state, synsent, synackrecv, establishing, established)
	if l.state == established || l.state == establishing {
		n, err = l.Conn.Write(b)
		return
	}
	ivlen := l.getIvlen()
	hdrlen := ivlen + pkthdrlen
	var p pkt
	p.pktlen = len(b)
	if l.state == repsent {
		p.noplen = len(l.local.keystr)
		hdrlen += p.noplen
	}
	buf := make([]byte, hdrlen+p.pktlen)
	switch l.state {
	case synsent:
		p.pktype = syn
	case repsent:
		p.pktype = rep
		copy(buf[ivlen+pkthdrlen:], []byte(l.local.keystr))
	case synackrecv:
		p.pktype = ack
	}
	p.encode(buf[ivlen:])
	l.encrypt(buf[:hdrlen])
	copy(buf[hdrlen:], b)
	n, err = l.Conn.Write(buf)
	n -= hdrlen
	return
}

func (l *Local) tryDialNewConn(sess *localSession) {
	sess.lock.Lock()
	defer sess.lock.Unlock()
	if sess.state != destroyed {
		return
	}
	sess.state = created
	go func() {
		conn, err := l.dialer()
		if err != nil {
			sess.lock.Lock()
			defer sess.lock.Unlock()
			if sess.state == created {
				sess.state = destroyed
			}
			return
		}
		sess.lock.Lock()
		defer sess.lock.Unlock()
		sess.Conn = conn
		sess.state = repsent
		go sess.readLoop()
	}()
}

func (l *Local) Write(b []byte) (n int, err error) {
	rr := int(atomic.AddInt32(&l.rr, 1))
	l.lock.RLock()
	k := len(l.keystr) != 0
	sess := l.localSessions[rr%len(l.localSessions)]
	l.lock.RUnlock()
	sess.lock.RLock()
	state := sess.state
	sess.lock.RUnlock()
	if state == destroyed {
		n, err = l.Write(b)
		if k {
			l.tryDialNewConn(sess)
		}
		return
	} else if state == created {
		n, err = l.Write(b)
		return
	}
	n, err = sess.Write(b)
	return
}

func (l *Local) SetReadDeadline(t time.Time) (err error) {
	if l.rtimer != nil {
		l.rtimer.Stop()
	}
	l.rtimer = time.NewTimer(t.Sub(time.Now()))
	return
}

func (l *Local) SetWriteDeadline(t time.Time) (err error) {
	if l.wtimer != nil {
		l.wtimer.Stop()
	}
	l.wtimer = time.NewTimer(t.Sub(time.Now()))
	return
}

func (l *Local) SetDeadline(t time.Time) (err error) {
	err = l.SetReadDeadline(t)
	if err != nil {
		return
	}
	err = l.SetWriteDeadline(t)
	return
}

type session struct {
	addr        net.Addr
	lock        sync.RWMutex
	subsessions []*subSession
	ts          time.Time
	rr          int32
	keystr      string
}

func (s *session) Addr() net.Addr {
	return s.addr
}

type subSession struct {
	sess      *session
	addr      net.Addr
	laddr     net.Addr
	fresh     bool
	ts        time.Time
	starttime time.Time
	state     int
}

func (s *subSession) Addr() net.Addr {
	return s.addr
}

func (s *subSession) LocalAddr() net.Addr {
	return s.laddr
}

func (s *subSession) Flush() {
	s.fresh = true
	now := time.Now()
	s.ts = now
	s.sess.ts = now
}

func (s *subSession) Decay() {
	s.fresh = false
}

func (s *subSession) IsFresh() bool {
	return s.fresh
}

type Server struct {
	net.PacketConn
	*cipher
	lock            sync.Mutex
	die             chan bool
	sessions        sync.Map
	sessionsWithKey sync.Map
	subSessions     sync.Map
	async           utils.AsyncRunner
	mixed           bool
	mixedCache      *utils.LRU
}

func Listen(conn net.PacketConn, method string, password string) (server *Server, err error) {
	server = &Server{
		PacketConn: conn,
		cipher: &cipher{
			method:   method,
			password: password,
			ivlen:    utils.GetIvLen(method),
		},
		die: make(chan bool),
	}
	return
}

func (s *Server) SetMixed(mixed bool) {
	if !mixed {
		if s.mixed {
			s.mixed = false
			s.mixedCache = nil
		}
		return
	}

	if s.mixed {
		return
	}

	s.mixed = true
	s.mixedCache = utils.NewLRU(6000, nil, nil)

	return
}

func (s *cipher) tryDecodePkt(b []byte) (p *pkt, nop []byte, payload []byte, err error) {
	n := len(b)
	ivlen := s.getIvlen()
	if n < ivlen+pkthdrlen {
		err = fmt.Errorf("packet is too short")
		return
	}
	b2 := make([]byte, ivlen+pkthdrlen)
	copy(b2, b)
	d, dec, err := s.decrypt(b2)
	if err != nil {
		return
	}
	b = b[ivlen+pkthdrlen:]
	p = decodePkt(d)
	if !p.valid(b) {
		err = fmt.Errorf("invalid noplen and pktlen")
		return
	}
	payload = b[p.noplen:]
	if p.noplen > 0 {
		nop = make([]byte, p.noplen)
		dec.Decrypt(nop, b[:p.noplen])
	}
	return
}

func (s *Server) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	b2 := b
	for {
		n, addr, err = s.PacketConn.ReadFrom(b2)
		if err != nil {
			return
		}
		addrstr := addr.String()
		v, ok := s.subSessions.Load(addrstr)
		if !ok {
			if s.mixed {
				_, ok = s.mixedCache.Load(addrstr)
				if ok {
					return
				}
			}
			p, nop, payload, err1 := s.tryDecodePkt(b2[:n])
			if err1 != nil {
				if s.mixed {
					s.mixedCache.Add(addrstr, nil)
					return
				}
				continue
			}
			nopstr := string(nop)
			if p.pktype == syn {
				sess := &session{addr: addr}
				subsess := &subSession{sess: sess, fresh: true, addr: addr, laddr: addr, state: synrecv}
				sess.subsessions = []*subSession{subsess}
				n = copy(b, payload)
				v, ok := s.subSessions.LoadOrStore(addrstr, subsess)
				if ok {
					subsess = v.(*subSession)
					addr = subsess.LocalAddr()
					subsess.Flush()
					return
				}
				s.sessions.Store(addrstr, sess)
				var keystr string
				for {
					keystr = string(utils.GetRandomBytes(sessionKeyLength))
					_, ok = s.sessionsWithKey.Load(keystr)
					if !ok {
						break
					}
				}
				s.sessionsWithKey.Store(keystr, sess)
				sess.keystr = keystr
				return
			} else if p.pktype == rep {
				if len(nopstr) != sessionKeyLength {
					continue
				}
				v, ok = s.sessionsWithKey.Load(nopstr)
				if !ok {
					continue
				}
				sess := v.(*session)
				subsess := &subSession{sess: sess, fresh: true, addr: addr, laddr: sess.Addr(), state: synrecv}
				n = copy(b, payload)
				v, ok = s.subSessions.LoadOrStore(addrstr, subsess)
				if ok {
					subsess = v.(*subSession)
					addr = subsess.LocalAddr()
					subsess.Flush()
					return
				}
				sess.lock.Lock()
				sess.subsessions = append(sess.subsessions, subsess)
				sess.lock.Unlock()
				addr = subsess.LocalAddr()
				return
			} else {
				continue
			}
		}
		subsess := v.(*subSession)
		subsess.Flush()
		addr = subsess.LocalAddr()
		if subsess.state == established {
			return
		}
		p, _, payload, err1 := s.tryDecodePkt(b2[:n])
		if err1 != nil {
			switch subsess.state {
			case ackrecv:
				subsess.state = establishing
				subsess.starttime = time.Now()
				return
			case establishing:
				if time.Now().Sub(subsess.starttime) > time.Second*30 {
					subsess.state = established
				}
				return
			default:
				continue
			}
		}
		n = copy(b, payload)
		switch p.pktype {
		default:
			continue
		case syn, rep:
			return
		case ack:
			if subsess.state == synrecv {
				subsess.state = ackrecv
			}
			return
		}
	}
}

func (s *Server) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	addrstr := addr.String()
	v, ok := s.sessions.Load(addrstr)
	if !ok {
		if s.mixed && s.mixedCache != nil {
			ok = s.mixedCache.Has(addrstr)
			if ok {
				return s.PacketConn.WriteTo(b, addr)
			}
		}
		return
	}
	sess := v.(*session)
	rr := int(atomic.AddInt32(&sess.rr, 1))
	sess.lock.RLock()
	if len(sess.subsessions) == 0 {
		sess.lock.RUnlock()
		s.sessions.Delete(addrstr)
		return
	}
	subsess := sess.subsessions[rr%len(sess.subsessions)]
	sess.lock.RUnlock()
	if subsess.state == synrecv {
		ivlen := s.getIvlen()
		var p pkt
		p.noplen = len(subsess.sess.keystr)
		p.pktype = synack
		p.pktlen = len(b)
		b2 := make([]byte, ivlen+pkthdrlen+p.noplen+p.pktlen)
		p.encode(b2[ivlen:])
		copy(b2[ivlen+pkthdrlen:], []byte(subsess.sess.keystr))
		s.encrypt(b2[:ivlen+pkthdrlen+p.noplen])
		copy(b2[ivlen+pkthdrlen+p.noplen:], b)
		_, err = s.PacketConn.WriteTo(b2, subsess.Addr())
		n = len(b)
		return
	}
	n, err = s.PacketConn.WriteTo(b, subsess.Addr())
	return
}

func (s *Server) Close() (err error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	select {
	case <-s.die:
	default:
		close(s.die)
	}
	err = s.PacketConn.Close()
	return
}
