dist_man3_MANS = tlsrpt_add_delivery_request_failure.3 \
            tlsrpt_add_mx_host_pattern.3 \
            tlsrpt_add_policy_string.3 \
            tlsrpt_cancel_delivery_request.3 \
            tlsrpt_close.3 \
            tlsrpt_errno_from_error_code.3 \
            tlsrpt_error_code_is_internal.3 \
            tlsrpt_finish_delivery_request.3 \
            tlsrpt_finish_policy.3 \
            tlsrpt_get_socket.3 \
            tlsrpt_init_delivery_request.3 \
            tlsrpt_init_policy.3 \
            tlsrpt_open.3 \
            tlsrpt_set_blocking.3 \
            tlsrpt_set_malloc_and_free.3 \
            tlsrpt_set_nonblocking.3 \
            tlsrpt_strerror.3 \
	    tlsrpt_version.3 \
	    tlsrpt_version_check.3

EXTRA_DIST = tlsrpt_add_delivery_request_failure.adoc \
            tlsrpt_add_mx_host_pattern.adoc \
            tlsrpt_add_policy_string.adoc \
            tlsrpt_cancel_delivery_request.adoc \
            tlsrpt_close.adoc \
            tlsrpt_errno_from_error_code.adoc \
            tlsrpt_error_code_is_internal.adoc \
            tlsrpt_finish_delivery_request.adoc \
            tlsrpt_finish_policy.adoc \
            tlsrpt_get_socket.adoc \
            tlsrpt_init_delivery_request.adoc \
            tlsrpt_init_policy.adoc \
            tlsrpt_open.adoc \
            tlsrpt_set_blocking.adoc \
            tlsrpt_set_malloc_and_free.adoc \
            tlsrpt_set_nonblocking.adoc \
            tlsrpt_strerror.adoc \
            tlsrpt_version.adoc \
            tlsrpt_version_check.adoc

.adoc.3:
	asciidoctor -b manpage $<

CLEANFILES = $(man3_MANS)
