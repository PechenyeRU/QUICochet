package main

import (
	"fmt"
	"os"

	"github.com/pechenyeru/quiccochet/internal/crypto"
	"github.com/spf13/cobra"
)

var keygenOutPrivate string

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate key pair",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate keys: %w", err)
		}

		// --out-private path: write the private key to a file with 0600
		// and never print it to stdout. The public key still goes to
		// stdout so the operator can share it with the peer.
		if keygenOutPrivate != "" {
			if err := os.WriteFile(keygenOutPrivate, []byte(keyPair.PrivateKeyBase64()), 0600); err != nil {
				return fmt.Errorf("write private key to %q: %w", keygenOutPrivate, err)
			}
			fmt.Println("╔════════════════════════════════════════════════════════════════╗")
			fmt.Println("║                    GENERATED KEY PAIR                          ║")
			fmt.Println("╠════════════════════════════════════════════════════════════════╣")
			fmt.Printf("║ Private Key: written to %-38s ║\n", truncForBox(keygenOutPrivate, 38))
			fmt.Printf("║ Public Key:  %-49s ║\n", keyPair.PublicKeyBase64())
			fmt.Println("╠════════════════════════════════════════════════════════════════╣")
			fmt.Println("║ Private key file mode: 0600. Keep it that way.                 ║")
			fmt.Println("║ Share the public key with your peer.                           ║")
			fmt.Println("╚════════════════════════════════════════════════════════════════╝")
			return nil
		}

		// Legacy stdout path: print both keys, and emit a stderr warning
		// so an operator who pasted the command into a shell understands
		// the private key is now in scrollback / history / CI logs.
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    GENERATED KEY PAIR                          ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════╣")
		fmt.Printf("║ Private Key: %-49s ║\n", keyPair.PrivateKeyBase64())
		fmt.Printf("║ Public Key:  %-49s ║\n", keyPair.PublicKeyBase64())
		fmt.Println("╠════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ INSTRUCTIONS:                                                  ║")
		fmt.Println("║ 1. Add private_key to client-config.json                       ║")
		fmt.Println("║ 2. Share public_key with your PEER                             ║")
		fmt.Println("║ 3. Add peer's public_key to your peer_public_key               ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, yellow("WARNING: private key printed to stdout — it is now in your"))
		fmt.Fprintln(os.Stderr, yellow("shell history, terminal scrollback, and any CI/SSH logs."))
		fmt.Fprintln(os.Stderr, yellow("Use --out-private FILE to write directly to a 0600 file."))
		return nil
	},
}

// truncForBox shortens s with a leading ellipsis if it would overflow
// the ASCII box, so the right border stays aligned regardless of the
// path length the operator passed via --out-private.
func truncForBox(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-(max-3):]
}

func init() {
	keygenCmd.Flags().StringVar(&keygenOutPrivate, "out-private", "",
		"write the private key to FILE (mode 0600) instead of printing it to stdout")
	mainCmd.AddCommand(keygenCmd)
}
