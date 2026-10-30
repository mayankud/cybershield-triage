# Security

This is a static site. There's no server, database, login or API key, and files you load stay in your browser.

What's in place:

- Uploaded text is always shown as plain text, never run as code
- The page only loads its own files and can't send data anywhere
- Upload size and row limits, and only known fields are read
- Exported CSV cells that could run as spreadsheet formulas are escaped

If you find a problem, please open a private security advisory on this repo (**Security → Report a vulnerability**) rather than a public issue.
