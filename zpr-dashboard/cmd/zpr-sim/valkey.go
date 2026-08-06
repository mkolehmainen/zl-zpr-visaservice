package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type valkey struct {
	conn net.Conn
	read *bufio.Reader
	err  error
}

func dial(addr string) (*valkey, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &valkey{conn: conn, read: bufio.NewReader(conn)}, nil
}

func (v *valkey) Close() error { return v.conn.Close() }

func (v *valkey) Err() error { return v.err }

func (v *valkey) cmd(args ...any) {
	if v.err != nil {
		return
	}

	var out strings.Builder
	fmt.Fprintf(&out, "*%d\r\n", len(args))
	for _, arg := range args {
		value := fmt.Sprint(arg)
		fmt.Fprintf(&out, "$%d\r\n%s\r\n", len(value), value)
	}

	if _, err := io.WriteString(v.conn, out.String()); err != nil {
		v.err = err
		return
	}

	v.err = v.reply()
}

func (v *valkey) reply() error {
	line, err := v.read.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return errors.New("empty reply")
	}

	tag, body := line[0], line[1:]
	switch tag {
	case '+', ':':
		return nil

	case '-':
		return errors.New(body)

	case '$':
		length, err := strconv.Atoi(body)
		if err != nil {
			return err
		}
		if length < 0 {
			return nil
		}

		_, err = io.CopyN(io.Discard, v.read, int64(length)+2)
		return err

	case '*':
		count, err := strconv.Atoi(body)
		if err != nil {
			return err
		}

		for range count {
			if err := v.reply(); err != nil {
				return err
			}
		}
		return nil
	}

	return fmt.Errorf("unexpected reply: %q", line)
}
