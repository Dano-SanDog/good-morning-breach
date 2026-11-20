// Command smtptest checks the GB_SMTP_* configuration and sends one fixed test
// message to an address the owner chooses. It never touches the database.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/alerting"
)

func main() {
	os.Exit(run())
}

func run() int {
	to := flag.String("to", "", "recipient address for the test message (required)")
	verifyOnly := flag.Bool("verify-only", false, "connect, negotiate TLS, and authenticate without sending a message")
	flag.Parse()
	if *to == "" && !*verifyOnly {
		fmt.Fprintln(os.Stderr, "error: -to is required unless -verify-only is set")
		return 2
	}

	config, configured, err := alerting.LoadSMTPConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL configuration: %v\n", err)
		return 1
	}
	if !configured {
		fmt.Fprintln(os.Stderr, "FAIL configuration: GB_SMTP_HOST is not set")
		return 1
	}
	fmt.Printf("ok   configuration: %s\n", config)

	sender, err := alerting.NewSMTPSender(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL configuration: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := sender.Verify(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL connect, TLS, or sign-in: %v\n", err)
		return 1
	}
	fmt.Println("ok   connected, TLS negotiated, signed in")
	if *verifyOnly {
		return 0
	}

	err = sender.SendText(ctx, *to, "Good Morning Breach test message",
		"This is a test message from Good Morning Breach.\nIf you can read it, email delivery works.")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL send: %v\n", err)
		return 1
	}
	fmt.Println("ok   message accepted by the SMTP server; check the inbox (and spam folder)")
	return 0
}
