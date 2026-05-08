# Config wizard happy-path: jump to Config tab, start a new config,
# walk through mode + transport + review, expect a Validate failure
# on save (Stage 2.1 wizard collects only mode + transport, the rest
# of the required fields land in Stage 2.2/2.3).

Output "/tmp/quiccochet-tui-eval/wizard.gif"

Set FontSize 14
Set Width 1200
Set Height 800
Set Theme "Catppuccin Mocha"

Type "/tmp/quiccochet-tui-bin ui --socket /tmp/quiccochet-fake.sock"
Enter
Sleep 1500ms

# Jump to Config tab
Type "2"
Sleep 800ms

# Start the wizard
Type "n"
Sleep 1s

Screenshot "/tmp/quiccochet-tui-eval/wizard_step_mode.png"

# Pick "Client" (default focused)
Enter
Sleep 800ms

Screenshot "/tmp/quiccochet-tui-eval/wizard_step_transport.png"

# Confirm udp transport
Enter
Sleep 800ms

Screenshot "/tmp/quiccochet-tui-eval/wizard_step_review.png"

# Field navigation: skip preview note, accept default save path,
# decline confirm — wizard should bounce back to step 0 instead of
# saving an incomplete config that would fail validation.
Tab
Sleep 300ms
Tab
Sleep 300ms
# leave confirm = false (default)
Enter
Sleep 1s

Screenshot "/tmp/quiccochet-tui-eval/wizard_aborted.png"

Type "q"
Sleep 500ms
