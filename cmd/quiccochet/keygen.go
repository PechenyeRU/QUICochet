package main

import (
	"fmt"
	"log"

	"github.com/pechenyeru/quiccochet/internal/crypto"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate key pair",
	Run: func(cmd *cobra.Command, args []string) {
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}

		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    GENERATED KEY PAIR                          ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════╣")
		fmt.Printf("║ Private Key: %-49s ║\n", keyPair.PrivateKeyBase64())
		fmt.Printf("║ Public Key:  %-49s ║\n", keyPair.PublicKeyBase64())
		fmt.Println("╠════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ INSTRUCTIONS:                                                  ║")
		fmt.Println("║ 1. Add private_key to YOUR client-config.json                         ║")
		fmt.Println("║ 2. Share public_key with your PEER                             ║")
		fmt.Println("║ 3. Add peer's public_key to your peer_public_key               ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	},
}

func init() {
	mainCmd.AddCommand(keygenCmd)
}
