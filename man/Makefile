#
#    Copyright (C) 2025 sys4 AG
#    Author Boris Lohner bl@sys4.de
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.
#    If not, see <http://www.gnu.org/licenses/>.
#

TARGETS = tlsrpt_add_delivery_request_failure.3
TARGETS += tlsrpt_add_mx_host_pattern.3
TARGETS += tlsrpt_add_policy_string.3
TARGETS += tlsrpt_cancel_delivery_request.3
TARGETS += tlsrpt_close.3
TARGETS += tlsrpt_errno_from_error_code.3
TARGETS += tlsrpt_error_code_is_internal.3
TARGETS += tlsrpt_finish_delivery_request.3
TARGETS += tlsrpt_finish_policy.3
TARGETS += tlsrpt_get_socket.3
TARGETS += tlsrpt_init_delivery_request.3
TARGETS += tlsrpt_init_policy.3
TARGETS += tlsrpt_open.3
TARGETS += tlsrpt_set_blocking.3
TARGETS += tlsrpt_set_malloc_and_free.3
TARGETS += tlsrpt_set_nonblocking.3
TARGETS += tlsrpt_strerror.3
TARGETS += tlsrpt_version.3
TARGETS += tlsrpt_version_check.3

.phony: all clean

all: ${TARGETS}

%.3 : %.adoc manpage-*.adoc Makefile
	asciidoctor -b manpage $<

clean:
	rm ${TARGETS} 
