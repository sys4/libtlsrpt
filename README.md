# libtlsrpt

The libtlsrpt project provides a low-level C Library which implements functions
that help generate TLSRPT datagrams. Included into a MTA it assists the MTA in
collecting and sending these datagrams to a TLSRPT reporting service where they
can be collected, summarized and finally sent to a mail platform that requests
TLSRPT reports as defined in in [RFC
8460](https://www.rfc-editor.org/rfc/rfc8460).

The Library has been released under [GNU Lesser General Public License
(LGPL)](COPYING) on purpose. We want to foster adoption of TLSRPT. Please feel
free to use it. If you have any questions regarding the project we would like
to ask you to either start a discussion or create an issue on GitHub.
Instructions on how to build and install libtlsrpt are located in
[INSTALL](INSTALL).


## About the project

The libtlsrpt project is part of a joint effort between the [Postfix
project](https://www.postfix.org), namely Wietse Venema who co-designed and
implemented TLSRPT with the help of libtlsrpt into Postfix, and
[sys4](https://sys4.de), who sponsored the project and whose team has put love
and efforts into libtlsrpt and
[tlsrpt-reporter](https://github.com/sys4/tlsrpt-reporter) to make this happen.

We want secure communications and we want people to feel free to communicate
whatever they want to about on the Internet. TLSRPT provides the reporting to
create visibilty about issues regarding secure communications. Use it! It's
[free](LICENSE).

Start a discussion or create a ticket on GitHub if you have specific questions
about the software provided by the project and / or join the
[TLSRPT mailing list](https://list.sys4.de/postorius/lists/tlsrpt.list.sys4.de/)
for general discussions on TLSRPT but also about this project.

