---
name: Bug report
about: Used to report a defect in the source code, scripts, etc... Post questions
  about usage in the Aircrack-ng forum at https://forum.aircrack-ng.org

---

Please read the following:

- **exploits MUST be sent to security@aircrack-ng.org.**
- Always test with current git master before opening a bug
- Use the search function to see if the bug you're about to post isn't a duplicate. If an existing bug is open and you have new information, update it. If a bug exists and is closed but still experience the issue with git master, reopen it and add useful information to it
- Unless linked, one bug per ticket.
- Don't worry about any of the items on the right panel (Assignee, Labels or Milestone), we will take care of them

The following must be taken to the forum first:
  - Not receiving any packets with airodump-ng or any other tool
  - Can't crack a network
  - Wireless card doesn't work
  - Channel -1. It is most likely a technique issue or possibly a misunderstanding, refer to the documentation and if still an issue, take it to the forum


**REMOVE ALL OF THE ABOVE TEXT**

# Issue type

**REMOVE THOSE WHICH DO NOT APPLY**
- Defect - Compilation or `make check` issue - Attach `config.log` and provide relevant system information such as `lscpu` - Make sure dependencies are installed
- Defect - Crash
- Defect - Incorrect value displayed/received/stored
- Defect - Unexpected behavior (obvious or confirmed in the forum)

# Defect
## How to reproduce the issue

A clear and concise list of steps describing the issue, relevant commands and errors/outputs. Such as: What command(s) did you run? What was displayed/happened? What did you expect to happen or be displayed? 

Do not use pastebin-type links and avoid images whenever possible. If the content (output or error) is text and can be copy/pasted, enclose it with backticks. If it is large, put it in a file and attach it to the ticket.

GitHub markdown guide: https://guides.github.com/features/mastering-markdown/

If you aren't familiar with bug reporting, [this](https://www.chiark.greenend.org.uk/~sgtatham/bugs.html) is an excellent read to help you describe bugs accurately

## Related issues

Link to any related issue from within the project or outside (GitHub or any other bug tracker or relevant forum post, etc...).
