#include <kernel.h>
#include <pagecache.h>
#include <tfs.h>
#include <unix.h>
#include <net.h>
#include <http.h>
#include <gdb.h>
#include <storage.h>
#include <symtab.h>
#include <virtio/virtio.h>

closure_function(2, 0, void, program_start,
                 buffer, elf, process, kp)
{
    exec_elf(bound(elf), bound(kp));
    closure_finish();
}

closure_function(3, 1, status, read_program_complete,
                 heap, h, process, kp, tuple, root,
                 buffer, b)
{
    tuple root = bound(root);
    if (table_find(root, sym(trace))) {
        rprintf("read program complete: %p ", root);
        rprintf("gitversion: %s ", gitversion);

        /* XXX - disable this until we can be assured that print_root
           won't go haywire on a large manifest... */
#if 0
        buffer b = allocate_buffer(transient, 64);
        print_root(b, root);
        buffer_print(b);
        deallocate_buffer(b);
        rprintf("\n");
#endif
       
    }
    storage_when_ready(closure(bound(h), program_start, b, bound(kp)));
    closure_finish();
    return STATUS_OK;
}

closure_function(0, 1, void, read_program_fail,
                 status, s)
{
    closure_finish();
    halt("read program failed %v\n", s);
}

/* XXX Note: temporarily putting these connection tests here until we
   get tracing hooked up... */

#if 0
/* limited to 1M on general heap at the moment... */
#define BULK_TEST_BUFSIZ (1ull << 20)
static buffer bulk_test_buffer(heap h)
{
    buffer b = allocate_buffer(h, BULK_TEST_BUFSIZ);
    for (int i = 0; i < (BULK_TEST_BUFSIZ / 10); i += 8) {
        bprintf(b, "%08d %08d %08d %08d %08d %08d %08d %08d\r\n",
                i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7);
    }
    return b;
}

/* raw tcp socket test */
closure_function(2, 1, status, test_recv,
                 heap, h,
                 buffer_handler, out,
                 buffer, b)
{
    buffer response = allocate_buffer(bound(h), 1024);
    buffer_handler out = bound(out);
    if (!b) {
        rprintf("telnet: remote closed\n");
        return STATUS_OK;
    }
    bprintf(response, "read: %b", b);
    apply(out, response);
    switch (*((u8*)buffer_ref(b, 0))) {
    case 'q':
        rprintf("telnet: remote sent quit\n");
        apply(out, 0);
        break;
    case 'b':
        rprintf("telnet: remote requested bulk buffer\n");
        apply(out, bulk_test_buffer(bound(h)));
        break;
    }
    return STATUS_OK;
}

closure_function(1, 1, buffer_handler, each_telnet_connection,
                 heap, h,
                 buffer_handler, out)
{
    heap h = bound(h);
    buffer response = allocate_buffer(h, 1024);
    rprintf("telnet: connection\n");
    bprintf(response, "nanos telnet test interface\r\n");
    apply(out, response);
    return closure(h, test_recv, h, out);
}
#endif

/* http debug test */
#if 0
closure_function(1, 3, void, each_test_request,
                 heap, h,
                 http_method, m, buffer_handler, out, value, v)
{
    status s = STATUS_OK;
    bytes total = 0;
    heap h = bound(h);
    rprintf("http: %s request via http: %v\n", http_request_methods[m], v);
    buffer u = table_find(v, sym(relative_uri));
    if (u && buffer_compare_with_cstring(u, "chunk")) {
        rprintf("chunked response\n");
        s = send_http_chunked_response(out, timm("Content-Type", "text/html"));

        if (!is_ok(s))
            goto out_fail;

        for (int i = 0; i < 10; i++) {
            buffer b = bulk_test_buffer(h);
            total += buffer_length(b);
            s = send_http_chunk(out, b);
            if (!is_ok(s))
                goto out_fail;
        }

        s = send_http_chunk(out, 0);
        if (!is_ok(s))
            goto out_fail;
    } else {
        buffer b = bulk_test_buffer(h);
        total += buffer_length(b);
        s = send_http_response(out, timm("Content-Type", "text/html"), b);
        if (!is_ok(s))
            goto out_fail;
    }

    rprintf("sent %d bytes\n", total);
    return;
  out_fail:
    msg_err("output buffer handler failed: %v\n", s);
}
#endif

closure_function(3, 0, void, startup,
                 kernel_heaps, kh, tuple, root, filesystem, fs)
{
    kernel_heaps kh = bound(kh);
    tuple root = bound(root);
    filesystem fs = bound(fs);

    /* kernel process is used as a handle for unix */
    process kp = init_unix(kh, root, fs);
    if (kp == INVALID_ADDRESS) {
	halt("unable to initialize unix instance; halt\n");
    }
    heap general = heap_general(kh);
    buffer_handler pg = closure(general, read_program_complete, general, kp, root);

#if 0
    if (table_find(root, sym(telnet))) {
        listen_port(general, 9090, closure(general, each_telnet_connection, general));
        rprintf("Debug telnet server started on port 9090\n");
    }

    http_listener hl = allocate_http_listener(general, 9090);
    assert(hl != INVALID_ADDRESS);
    http_register_uri_handler(hl, "test", closure(general, each_test_request, general));

    if (table_find(root, sym(http))) {
        status s = listen_port(general, 9090, connection_handler_from_http_listener(hl));
        if (!is_ok(s))
            halt("listen_port failed for http listener: %v\n", s);
        rprintf("Debug http server started on port 9090\n");
    }
#endif
    value p = table_find(root, sym(program));
    assert(p);
    tuple pro = resolve_path(root, split(general, p, '/'));
    if (table_find(root, sym(exec_protection)))
        table_set(pro, sym(exec), null_value);  /* set executable flag */
    init_network_iface(root);
    filesystem_read_entire(fs, pro, heap_backed(kh), pg, closure(general, read_program_fail));
    closure_finish();
}

thunk create_init(kernel_heaps kh, tuple root, filesystem fs)
{
    return closure(heap_general(kh), startup, kh, root, fs);
}

closure_function(2, 1, status, kernel_read_complete,
                 filesystem, fs, boolean, destroy_fs,
                 buffer, b)
{
    add_elf_syms(b, 0);
    deallocate_buffer(b);
    if (bound(destroy_fs))
        destroy_filesystem(bound(fs));
    closure_finish();
    return STATUS_OK;
}

closure_function(4, 2, void, bootfs_complete,
                 kernel_heaps, kh, tuple, root, boolean, klibs_in_bootfs, boolean, ingest_kernel_syms,
                 filesystem, fs, status, s)
{
    tuple boot_root = filesystem_getroot(fs);
    tuple c = children(boot_root);
    assert(c);
    if (bound(klibs_in_bootfs))
        init_klib(bound(kh), fs, bound(root), boot_root);

    if (bound(ingest_kernel_syms)) {
        table_foreach(c, k, v) {
            if (!buffer_strcmp(symbol_string(k), "kernel")) {
                kernel_heaps kh = bound(kh);
                filesystem_read_entire(fs, v, heap_backed(kh),
                                       closure(heap_general(kh),
                                               kernel_read_complete, fs, !bound(klibs_in_bootfs)),
                                       ignore_status);
                break;
            }
        }
    }
    closure_finish();
}

filesystem_complete bootfs_handler(kernel_heaps kh, tuple root,
                                   boolean klibs_in_bootfs,
                                   boolean ingest_kernel_syms)
{
    return closure(heap_general(kh), bootfs_complete,
                   kh, root, klibs_in_bootfs, ingest_kernel_syms);
}
