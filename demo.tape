Output demo.gif
Set FontSize 14
Set Width 1200
Set Height 800
Set Theme "dracula"
Set TypingSpeed 40

# Scene 1: Create desktop launcher with validation
# This demonstrates the full LNTA workflow: fingerprint, bwrap sandboxing,
# unified diff preview, and desktop-file-validate verification receipt
Type "lnta \"create a desktop launcher for my local script ~/bin/backup-ui and validate it\""
Enter
Sleep 3s

# Scene 2: Instant rollback with lnta undo
# Shows the zero-friction undo capability - reverts in ~1 second
Type "lnta undo"
Enter
Sleep 2s

# Scene 3: Pipe ingestion + LLM analysis
# Demonstrates journalctl output piped to lnta for failure explanation
Type "journalctl -n 20 | lnta \"explain what's failing\""
Enter
Sleep 3s