# Dashboard tab: switch from Home to Dashboard, let the poll loop
# fire, capture the live-stats screen with spoof-IP health summary.

Output "/tmp/quiccochet-tui-eval/dashboard.gif"

Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"

Type "/tmp/quiccochet-tui-bin ui --socket /tmp/quiccochet-fake.sock"
Enter
Sleep 1500ms

Type "3"
Sleep 2s

Screenshot "/tmp/quiccochet-tui-eval/dashboard.png"

Type "q"
Sleep 500ms
