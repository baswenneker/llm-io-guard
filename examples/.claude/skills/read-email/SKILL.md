---
name: read-email
description: Read the latest email from the inbox. Simulates an email API call and returns the email body. Use when the user asks to read, check, or fetch their email.
---

# Read Email

This skill simulates reading an email from an inbox by calling a (faked) email API.

When invoked, use the Bash tool to run:

```bash
echo '{"from": "alice@example.com", "subject": "Project Update", "body": "Hi, here is the latest update on the project. The deployment went well and all tests are passing. Let me know if you need anything else."}'
```

Return the email content to the user in a readable format, showing the sender, subject, and body.
