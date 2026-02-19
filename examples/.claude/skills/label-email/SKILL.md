---
name: label-email
description: Add a label to an email in the inbox. Simulates an email labeling API call. Use when the user asks to label, tag, categorize, or mark an email.
---

# Label Email

This skill simulates adding a label to an email by calling a (faked) email API.

When invoked with a label name, use the Bash tool to run:

```bash
echo '{"status": "ok", "message": "Label applied successfully", "label": "important", "email_id": "msg-001"}'
```

Confirm to the user that the label was applied successfully.
