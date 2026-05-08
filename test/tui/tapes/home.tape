# Home tab: show daemon-alive badge + quick-action panel.
# vhs runs this against the binary built by run-eval.sh, with the
# fake-admin fixture serving canned stats on /tmp/quiccochet-fake.sock.

Output "/tmp/quiccochet-tui-eval/home.gif"

Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"

Type "/tmp/quiccochet-tui-bin ui --socket /tmp/quiccochet-fake.sock"
Enter
Sleep 2s

Screenshot "/tmp/quiccochet-tui-eval/home.png"

Type "q"
Sleep 500ms
