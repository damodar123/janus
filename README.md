# Note

As part of my coursework at Arizona State University, I had the opportunity to explore the classic problem called the Containment Problem. The Containment Problem is the problem of containing untrusted processes so that unintended information leakage does not occur. While exploring this topic I had the honor of studying the works of Tal Garfinkel and David Wagner. I had the pleasure of reading David Wagner's _Janus: an approach for the confinement of untrusted helper applications_, which he wrote while he was still in grad school, and study how the problem of process containment was approached in the past. Since his paper was written, there have been great innovations in sandboxing and process containment, including the use of multiple instances of global Linux namespaces to facilitate partial virtualization, which made its way into the Linux kernel itself. My individualized instruction under Dr. Bazzi has been an exploration of software security throughout history.

This repo contains the original Janus code for Linux kernel 2.2.x, before the 2.6.x+ era when the multiple instances of global Linux namespaces were introduced. In the 2.2.x versions of the Linux kernel, system call interposition was possible by overwriting the syscall table. Overwriting the syscall table was something only Linux kernel modules could do. Since then, direct rewrites of the syscall tables were not allowed, and instead syscall interposition were commonly done through the `/proc` filesystem nodes. It is humbling to see a mind much greater than mine at work.

The Wiki for this repo has my comments about the Janus code as I try to understand how it works. The branch `annotation` contains comments in the code that I have added that explains key parts of the Janus code.

# Original Readme

Janus version 2.0.1

Janus is a security package for application sandboxing.

Janus is currently in alpha pre-release, please read the RELEASE_NOTES
for more information about its use and distribution.

Janus has a dedicated mailing list for reporting bugs, sending patches,
release announcements etc.

You can subscribe to the dedicated mailing list by sending an email
message to majordomo@ninja.cs.berkeley.edu with "subscribe janus"
in the body of your message.

For instructions on installing janus see INSTALL in this directory.

For examples of janus policies see the examples/ directory.

For documentation on how Janus works and how to use Janus see docs/MANUAL.


Tal Garfinkel and David Wagner, University of California, Berkeley
