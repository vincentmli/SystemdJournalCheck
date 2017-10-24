/*
	Allow running as cron job
*/

package main

import (

	//    "code.google.com/p/go.crypto/ssh"
	//    "github.com/pkg/sftp"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

func WatchJournal(fromcfg ClientConfig, tocfg ClientConfig) {

	if journal_open() < 0 {

		log.Fatal("Failed to open the journal!")
	}
	if journal_flush_matches() < 0 {

		log.Fatal("Failed to flush the journal filter!")
	}
	if len(fromcfg.Journald.Match) < 1 {

		for _, v := range fromcfg.Journald.Match {

			if journal_add_match(v) < 0 {

				log.Fatal("Failed to add match in journal!")
			}
		}
	}
	if journal_seek_tail() < 0 {

		log.Fatal("Failed to skip to end of journal!")
	}
	/*
		systemd feature/ bug: without a sd_journal_previous,
		sd_journal_seek_tail has no effect
	*/
	if journal_previous() < 0 {

		log.Fatal("Failed to go back in journal!")
	}

	log.Print("Now watching Journal")

	const timeout_usec int = -1
	for {

		time.Sleep(time.Duration(fromcfg.Journald.Sleep) * time.Second)

		next := journal_next()
		if next == 0 {

			// at end of journal
			//log.Print("next before continue ", next)
			/* Reached the end, let's wait for changes, and try again */
			next = journal_wait(timeout_usec)
			if next < 0 {
				log.Fatal("Failed to wait for changes")
				break
			}
			continue
		} else if next < 0 {

			// failed to iterate to next entry
			log.Print("Failed to iterate to next entry in journal!")
			break
		}

		if next > 0 {

			var event string
			if journal_get_data(&event) < 0 {

				log.Print("Failed to get journal data!")
			}

			event = strings.Split(event, "MESSAGE=")[1]

			for _, v := range fromcfg.Journald.TriggerWords {

				if strings.Contains(event, v) {

					notice := fmt.Sprintf("Security Event Occurred on %s %s %s", GetHostName(), "at", time.Now())
					log.Print(notice)

					err := SendEmail(
						fromcfg.Notifications.Email.Host,
						fromcfg.Notifications.Email.Port,
						fromcfg.Notifications.Email.Username,
						fromcfg.Notifications.Email.Password,
						tocfg.Notifications.Email.To,
						notice,
						event)
					if err != nil {

						log.Print(err)
					}
				}
			}

		}
	}
	if journal_close() < 0 {

		log.Fatal("Failed to close the journal!")
	}
}

func init() {

	flag.StringVar(&ConfigFile, "f", "./from.json", "The email sender file")
	flag.StringVar(&ToFile, "t", "./to.json", "The email receiver file")
	flag.StringVar(&KeyFile, "k", "./key.json", "The key to decrypt password key file")
	flag.Parse()
}

func main() {

	fromcfg, err := GetCFG(ConfigFile)
	if err != nil {

		fmt.Printf("Could not parse config settings. You may have to remove %s\n", ConfigFile)
	}
	tocfg, err := GetCFG(ToFile)
	if err != nil {

		fmt.Printf("Could not parse config settings. You may have to remove %s\n", ToFile)
	}
	kcfg, err := GetCFG(KeyFile)
	if err != nil {

		fmt.Printf("Could not parse config settings. You may have to remove %s\n", KeyFile)
	}
	encrypted, err := strconv.Unquote(`"` + fromcfg.Notifications.Email.Password + `"`)
	if err != nil {
		log.Fatal(err)
	}
	decrypted_key, err := GetKey(kcfg)
	if err != nil {
		log.Fatal(err)
	}
	password, err := PlainText(encrypted, decrypted_key)
	if err != nil {
		log.Fatal(err)
	}
	fromcfg.Notifications.Email.Password = string(password)
	//	fmt.Printf("fromcfg.Notifications.Email.Password %s\n", fromcfg.Notifications.Email.Password)
	WatchJournal(fromcfg, tocfg)
}
