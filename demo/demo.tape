Output demo/llm-scanner.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 620
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 12ms

Hide
Type "cd ~/projects/llm-scanner && source venv/bin/activate"
Enter
Sleep 1s
Type "python target/app.py < /dev/null > /dev/null 2>&1 &"
Enter
Sleep 3s
Type "curl -s -o /dev/null localhost:5000/chat -d @/tmp/benign.json -H 'Content-Type: application/json'"
Enter
Sleep 2s
Type "export PS1='$ ' && clear"
Enter
Sleep 2s
Show

# Act 1: normal request, normal answer
Type "curl -s localhost:5000/chat -H 'Content-Type: application/json' -d @/tmp/benign.json"
Enter
Sleep 3s

# Act 1: a jailbreak gets through
Type "curl -s localhost:5000/chat -H 'Content-Type: application/json' -d @/tmp/jailbreak.json"
Enter
Sleep 4s

# Act 1: a malformed payload leaks the system prompt
Type "curl -s localhost:5000/chat -H 'Content-Type: application/json' -d @/tmp/malformed.json"
Enter
Sleep 5s

Hide
Type "clear"
Enter
Sleep 1s
Show

# Act 2: the scanner finds all of it automatically
Type "python -m scanner.main --no-target --max-rows 8"
Enter
Sleep 22s

Type "echo $?"
Enter
Sleep 3s