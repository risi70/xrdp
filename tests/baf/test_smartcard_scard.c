/*
 * Unit + robustness tests for the MS-RDPESC smart-card redirection response
 * parsers in sesman/chansrv/smartcard_pcsc.c (the --enable-smartcard code).
 *
 * The scard_function_*_return() parsers decode client-controlled [MS-RDPESC]
 * IOCTL responses (see docs/references/microsoft/NOTES.md and
 * broker-auth/UPSTREAM-MS-RDPESC-REVIEW.md). They are static, so we #include the
 * translation unit directly and stub its two external collaborators:
 *   - the request/send side (scard_send_*), which lives in smartcard.c; and
 *   - the trans output layer, stubbed so the reply is marshalled into a real
 *     init_stream() buffer -- an undersized/overflowing reply is therefore
 *     caught by AddressSanitizer.
 *
 * Build/run under -fsanitize=address,undefined for the security assertions to
 * have teeth (see tests/baf/Makefile.am, guarded by XRDP_SMARTCARD).
 *
 * Vectors: positive decodes plus the F1-F9 findings from the upstream review
 * (truncated headers, negative/oversized lengths, unbounded counts).
 */

#include <config_ac.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "arch.h"
#include "parse.h"
#include "trans.h"
#include "smartcard_internal.h"

/* chansrv globals referenced by smartcard_pcsc.c's socket setup. */
char g_display_str[256] = "10.0";

/* ------------------------------------------------------------------ */
/* Stubs for the send side (smartcard.c is not linked into this test). */
/* ------------------------------------------------------------------ */
int scard_send_establish_context(void *u, int scope) { (void)u; (void)scope; return 0; }
int scard_send_release_context(void *u, char *c, int cb) { (void)u; (void)c; (void)cb; return 0; }
int scard_send_is_valid_context(void *u, char *c, int cb) { (void)u; (void)c; (void)cb; return 0; }
int scard_send_list_readers(void *u, char *c, int cb, char *g, int n, int w)
{ (void)u; (void)c; (void)cb; (void)g; (void)n; (void)w; return 0; }
int scard_send_get_status_change(void *u, char *c, int cb, int w, tui32 t,
                                 tui32 nr, READER_STATE *rsa)
{ (void)u; (void)c; (void)cb; (void)w; (void)t; (void)nr; (void)rsa; return 0; }
int scard_send_connect(void *u, char *c, int cb, int w, READER_STATE *rs)
{ (void)u; (void)c; (void)cb; (void)w; (void)rs; return 0; }
int scard_send_reconnect(void *u, char *c, int cb, char *cd, int cdb, READER_STATE *rs)
{ (void)u; (void)c; (void)cb; (void)cd; (void)cdb; (void)rs; return 0; }
int scard_send_begin_transaction(void *u, char *c, int cb, char *cd, int cdb)
{ (void)u; (void)c; (void)cb; (void)cd; (void)cdb; return 0; }
int scard_send_end_transaction(void *u, char *c, int cb, char *cd, int cdb, tui32 d)
{ (void)u; (void)c; (void)cb; (void)cd; (void)cdb; (void)d; return 0; }
int scard_send_status(void *u, int w, char *c, int cb, char *cd, int cdb, int rl, int al)
{ (void)u; (void)w; (void)c; (void)cb; (void)cd; (void)cdb; (void)rl; (void)al; return 0; }
int scard_send_disconnect(void *u, char *c, int cb, char *cd, int cdb, int d)
{ (void)u; (void)c; (void)cb; (void)cd; (void)cdb; (void)d; return 0; }
int scard_send_transmit(void *u, char *c, int cb, char *cd, int cdb,
                        char *sd, int sb, int rb,
                        struct xrdp_scard_io_request *si,
                        struct xrdp_scard_io_request *ri)
{ (void)u; (void)c; (void)cb; (void)cd; (void)cdb; (void)sd; (void)sb; (void)rb;
  (void)si; (void)ri; return 0; }
int scard_send_control(void *u, char *c, int cb, char *cd, int cdb,
                       char *sd, int sb, int rb, int cc)
{ (void)u; (void)c; (void)cb; (void)cd; (void)cdb; (void)sd; (void)sb; (void)rb;
  (void)cc; return 0; }
int scard_send_cancel(void *u, char *c, int cb) { (void)u; (void)c; (void)cb; return 0; }
int scard_send_get_attrib(void *u, char *card, int cb, READER_STATE *rs)
{ (void)u; (void)card; (void)cb; (void)rs; return 0; }

/* Pull in the unit under test (static parsers + helpers). The real trans layer
 * from libcommon is used (trans_get_out_s -> init_stream on a real heap buffer,
 * so an oversized/overflowing reply trips ASan); only the wire send is faked. */
#include "smartcard_pcsc.c"

/* Discard sender so trans_force_write() succeeds without a live socket. */
static int
fake_trans_send(struct trans *self, const char *data, int len)
{
    (void)self; (void)data;
    return len;
}

/* ------------------------------------------------------------------ */
/* Tiny test harness.                                                  */
/* ------------------------------------------------------------------ */
static int g_checks = 0;
static int g_fails = 0;
static struct trans *g_con;   /* real trans, discard sender (set in main) */

#define CHECK(cond, msg) do {                                            \
        g_checks++;                                                      \
        if (!(cond)) { g_fails++;                                        \
            printf("  FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); } \
    } while (0)

/* Byte-buffer builder for hand-encoded [MS-RDPESC] responses. */
struct bb { unsigned char d[131072]; int n; };
static void bb_reset(struct bb *b) { b->n = 0; }
static void bb_u8(struct bb *b, unsigned v) { b->d[b->n++] = (unsigned char)v; }
static void bb_u32(struct bb *b, tui32 v)
{ bb_u8(b, v & 0xff); bb_u8(b, (v >> 8) & 0xff);
  bb_u8(b, (v >> 16) & 0xff); bb_u8(b, (v >> 24) & 0xff); }
static void bb_zeros(struct bb *b, int n) { while (n-- > 0) { bb_u8(b, 0); } }
static void bb_bytes(struct bb *b, const void *p, int n)
{ memcpy(b->d + b->n, p, n); b->n += n; }

static void in_from_bb(struct stream *s, struct bb *b)
{
    s->data = (char *)b->d;
    s->p = (char *)b->d;
    s->end = (char *)b->d + b->n;
    s->size = b->n;
    s->next_packet = NULL;
}

/* Register a uds client exactly as the real accept path (my_pcsc_trans_conn_in)
 * does: create it AND add it to g_uds_clients so get_uds_client_by_id() finds
 * it and the parsers actually run (not bail early). */
static struct pcsc_uds_client *
new_client(int *id_out)
{
    struct pcsc_uds_client *c = create_uds_client(g_con);
    if (g_uds_clients == 0)
    {
        g_uds_clients = list_create();
    }
    list_add_item(g_uds_clients, (tintptr) c);
    if (c != NULL && id_out != NULL) { *id_out = c->uds_client_id; }
    return c;
}

/* ================================================================== */
/* Positive vectors                                                    */
/* ================================================================== */
static void test_positive(void)
{
    struct bb b;
    struct stream in;
    int id;
    struct pcsc_uds_client *c;

    printf("[positive decodes]\n");

    /* EstablishContext_Return: 28-byte header, u32 len=8, 8 ctx bytes */
    c = new_client(&id);
    bb_reset(&b);
    bb_zeros(&b, 28);
    bb_u32(&b, 8);
    bb_bytes(&b, "CTX01234", 8);
    in_from_bb(&in, &b);
    CHECK(scard_function_establish_context_return((void *)(tintptr)id, &in, b.n, 0) == 0,
          "establish_context valid returns success");
    CHECK(c->contexts != NULL && c->contexts->count == 1,
          "establish_context added exactly one context");

    /* Transmit_Return: no PCI (val=0), cbRecvLength=4, 4 bytes */
    {
        struct pcsc_transmit *pt = (struct pcsc_transmit *)
                                   g_malloc(sizeof(struct pcsc_transmit), 1);
        int id2;
        new_client(&id2);
        pt->uds_client_id = id2;
        pt->cbRecvLength = 4;
        bb_reset(&b);
        bb_zeros(&b, 20);
        bb_u32(&b, 0);          /* pioRecvPci referent = NULL */
        bb_zeros(&b, 4);
        bb_u32(&b, 1);          /* pbRecvBuffer referent != NULL */
        bb_u32(&b, 4);          /* cbRecvLength */
        bb_bytes(&b, "9000", 4);
        in_from_bb(&in, &b);
        CHECK(scard_function_transmit_return((void *)pt, &in, b.n, 0) == 0,
              "transmit valid (4-byte APDU) returns success");
    }

    /* Transmit_Return: no PCI and no recv buffer (val2=0) -> the reply copies
     * a NULL source of length 0; must be a clean no-op (no memcpy(NULL) UB). */
    {
        struct pcsc_transmit *pt = (struct pcsc_transmit *)
                                   g_malloc(sizeof(struct pcsc_transmit), 1);
        int id2b;
        new_client(&id2b);
        pt->uds_client_id = id2b;
        pt->cbRecvLength = 0;
        bb_reset(&b);
        bb_zeros(&b, 20);
        bb_u32(&b, 0);          /* pioRecvPci NULL */
        bb_zeros(&b, 4);
        bb_u32(&b, 0);          /* pbRecvBuffer NULL */
        in_from_bb(&in, &b);
        CHECK(scard_function_transmit_return((void *)pt, &in, b.n, 0) == 0,
              "transmit valid (no PCI, no recv buffer) returns success");
    }

    /* GetStatusChange_Return: cReaders=1, one reader record (48 bytes) */
    {
        int id3;
        new_client(&id3);
        bb_reset(&b);
        bb_zeros(&b, 28);
        bb_u32(&b, 1);          /* cReaders */
        bb_u32(&b, 0x0022);     /* current_state */
        bb_u32(&b, 0x0122);     /* event_state */
        bb_u32(&b, 4);          /* atr_len */
        bb_zeros(&b, 36);       /* atr[36] */
        in_from_bb(&in, &b);
        CHECK(scard_function_get_status_change_return((void *)(tintptr)id3, &in, b.n, 0) == 0,
              "get_status_change valid (1 reader) returns success");
    }
}

/* ================================================================== */
/* Security / robustness vectors (F1-F9). Under ASan a missing bound   */
/* aborts; otherwise we assert the parser fails closed (returns 1).    */
/* ================================================================== */
static void test_security(void)
{
    struct bb b;
    struct stream in;
    int id;

    printf("[security / robustness — F1-F9]\n");

    /* F3: truncated EstablishContext header (10 of 32 bytes). */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 10);
    in_from_bb(&in, &b);
    CHECK(scard_function_establish_context_return((void *)(tintptr)id, &in, b.n, 0) == 1,
          "F3: truncated establish_context header fails closed");

    /* F7: negative context_bytes (0xFFFFFFFF) must not stack-smash context[16]. */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 28); bb_u32(&b, 0xFFFFFFFF); bb_zeros(&b, 16);
    in_from_bb(&in, &b);
    CHECK(scard_function_establish_context_return((void *)(tintptr)id, &in, b.n, 0) == 1,
          "F7: negative context_bytes rejected");

    /* F7: oversized context_bytes (64 > 16). */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 28); bb_u32(&b, 64); bb_zeros(&b, 64);
    in_from_bb(&in, &b);
    CHECK(scard_function_establish_context_return((void *)(tintptr)id, &in, b.n, 0) == 1,
          "F7: oversized context_bytes rejected");

    /* F1/F2: transmit cbRecvLength huge but stream short -> OOB read + out_s
     * overflow if unguarded. */
    {
        struct pcsc_transmit *pt = (struct pcsc_transmit *)
                                   g_malloc(sizeof(struct pcsc_transmit), 1);
        new_client(&id); pt->uds_client_id = id; pt->cbRecvLength = 4;
        bb_reset(&b);
        bb_zeros(&b, 20); bb_u32(&b, 0); bb_zeros(&b, 4);
        bb_u32(&b, 1);          /* pbRecvBuffer present */
        bb_u32(&b, 0x40000000); /* cbRecvLength = 1 GiB */
        /* no payload follows */
        in_from_bb(&in, &b);
        CHECK(scard_function_transmit_return((void *)pt, &in, b.n, 0) == 1,
              "F1/F2: transmit oversized cbRecvLength fails closed");
    }

    /* [MS-RDPESC] range: transmit cbRecvLength beyond 66560 rejected even when
     * the bytes are present in-buffer (spec-conformant hardening). */
    {
        struct pcsc_transmit *pt = (struct pcsc_transmit *)
                                   g_malloc(sizeof(struct pcsc_transmit), 1);
        new_client(&id); pt->uds_client_id = id; pt->cbRecvLength = 0;
        bb_reset(&b);
        bb_zeros(&b, 20); bb_u32(&b, 0); bb_zeros(&b, 4);
        bb_u32(&b, 1);          /* pbRecvBuffer present */
        bb_u32(&b, 70000);      /* cbRecvLength > 66560 */
        bb_zeros(&b, 70000);    /* bytes actually present */
        in_from_bb(&in, &b);
        CHECK(scard_function_transmit_return((void *)pt, &in, b.n, 0) == 1,
              "MS-RDPESC range: transmit cbRecvLength > 66560 rejected in-buffer");
    }

    /* F1: transmit extra_bytes (PCI) huge but stream short. */
    {
        struct pcsc_transmit *pt = (struct pcsc_transmit *)
                                   g_malloc(sizeof(struct pcsc_transmit), 1);
        new_client(&id); pt->uds_client_id = id; pt->cbRecvLength = 0;
        bb_reset(&b);
        bb_zeros(&b, 20); bb_u32(&b, 1); /* pioRecvPci present */
        bb_zeros(&b, 8); bb_u32(&b, 0); bb_u32(&b, 0);
        bb_u32(&b, 0x7fffffff);          /* extra_bytes */
        in_from_bb(&in, &b);
        CHECK(scard_function_transmit_return((void *)pt, &in, b.n, 0) == 1,
              "F1: transmit oversized PCI extra_bytes fails closed");
    }

    /* F6: connect card_bytes oversized (64 -> card[16] heap overflow). */
    {
        struct pcsc_uds_client *c = new_client(&id);
        char ctxbuf[] = "ctx";
        c->connect_context = uds_client_add_context(c, ctxbuf, 3);
        bb_reset(&b);
        bb_zeros(&b, 36); bb_u32(&b, 0x0002); /* dwActiveProtocol */
        bb_u32(&b, 64);                        /* card_bytes */
        bb_zeros(&b, 64);
        in_from_bb(&in, &b);
        CHECK(scard_function_connect_return((void *)(tintptr)id, &in, b.n, 0) == 1,
              "F6: connect oversized card_bytes rejected (no card[16] overflow)");
    }

    /* F6: connect card_bytes negative. */
    {
        struct pcsc_uds_client *c = new_client(&id);
        char ctxbuf[] = "ctx";
        c->connect_context = uds_client_add_context(c, ctxbuf, 3);
        bb_reset(&b);
        bb_zeros(&b, 36); bb_u32(&b, 0x0002);
        bb_u32(&b, 0xFFFFFFFF);
        in_from_bb(&in, &b);
        CHECK(scard_function_connect_return((void *)(tintptr)id, &in, b.n, 0) == 1,
              "F6: connect negative card_bytes rejected");
    }

    /* F5: get_status_change cReaders unbounded (INT_MAX). */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 28); bb_u32(&b, 0x7fffffff);
    in_from_bb(&in, &b);
    CHECK(scard_function_get_status_change_return((void *)(tintptr)id, &in, b.n, 0) == 1,
          "F5: get_status_change unbounded cReaders rejected");

    /* F5: cReaders plausible but stream too short for the records. */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 28); bb_u32(&b, 10); bb_zeros(&b, 20);
    in_from_bb(&in, &b);
    CHECK(scard_function_get_status_change_return((void *)(tintptr)id, &in, b.n, 0) == 1,
          "F5: get_status_change short reader array fails closed");

    /* F3: control truncated header. */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 8);
    in_from_bb(&in, &b);
    CHECK(scard_function_control_return((void *)(tintptr)id, &in, b.n, 0) == 1,
          "F3: control truncated header fails closed");

    /* F1/F2: control cbRecvLength huge, short stream. */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 28); bb_u32(&b, 0x40000000);
    in_from_bb(&in, &b);
    CHECK(scard_function_control_return((void *)(tintptr)id, &in, b.n, 0) == 1,
          "F1/F2: control oversized cbRecvLength fails closed");

    /* F7: status dwAtrLen > 32 must not over-read attr[32]. Valid header,
     * dwReaderLen=0 so no name; expect success with the ATR clamped. */
    {
        struct pcsc_status *ps = (struct pcsc_status *)
                                 g_malloc(sizeof(struct pcsc_status), 1);
        new_client(&id); ps->uds_client_id = id; ps->cchReaderLen = 0;
        bb_reset(&b);
        bb_zeros(&b, 16); bb_zeros(&b, 4);
        bb_u32(&b, 0);           /* dwReaderLen = 0 */
        bb_zeros(&b, 4);
        bb_u32(&b, 0);           /* dwState */
        bb_u32(&b, 2);           /* dwProtocol */
        bb_zeros(&b, 32);        /* attr[32] */
        bb_u32(&b, 1000);        /* dwAtrLen (>32) */
        in_from_bb(&in, &b);
        CHECK(scard_function_status_return((void *)ps, &in, b.n, 0) == 0,
              "F7: status oversized dwAtrLen clamped (no attr[32] over-read)");
    }

    /* status dwState with the high bit set must not index g_ms2pc[] negatively
     * (dwState is read into a signed int; found by fuzzing). */
    {
        struct pcsc_status *ps = (struct pcsc_status *)
                                 g_malloc(sizeof(struct pcsc_status), 1);
        new_client(&id); ps->uds_client_id = id; ps->cchReaderLen = 0;
        bb_reset(&b);
        bb_zeros(&b, 16); bb_zeros(&b, 4);
        bb_u32(&b, 0);           /* dwReaderLen = 0 */
        bb_zeros(&b, 4);
        bb_u32(&b, 0x80000005);  /* dwState, high bit set */
        bb_u32(&b, 2);           /* dwProtocol */
        bb_zeros(&b, 32);        /* attr[32] */
        bb_u32(&b, 4);           /* dwAtrLen */
        in_from_bb(&in, &b);
        CHECK(scard_function_status_return((void *)ps, &in, b.n, 0) == 0,
              "status high-bit dwState does not index g_ms2pc negatively");
    }

    /* F3/F4: list_readers truncated header. */
    {
        struct pcsc_list_readers *pl = (struct pcsc_list_readers *)
                                       g_malloc(sizeof(struct pcsc_list_readers), 1);
        new_client(&id); pl->uds_client_id = id; pl->cchReaders = 64;
        bb_reset(&b); bb_zeros(&b, 8);
        in_from_bb(&in, &b);
        CHECK(scard_function_list_readers_return((void *)pl, &in, b.n, 0) == 1,
              "F3/F4: list_readers truncated header fails closed");
    }

    /* F3: every status==0 parser with a completely empty stream. */
    {
        char empty[1];
        struct pcsc_transmit *pt;
        struct pcsc_status *ps;
        struct pcsc_list_readers *pl;

        new_client(&id);
        in.data = empty; in.p = empty; in.end = empty; in.size = 0; in.next_packet = NULL;
        CHECK(scard_function_establish_context_return((void *)(tintptr)id, &in, 0, 0) == 1,
              "F3: empty stream establish_context fails closed");

        new_client(&id);
        in.p = in.end = in.data = empty; in.size = 0;
        CHECK(scard_function_control_return((void *)(tintptr)id, &in, 0, 0) == 1,
              "F3: empty stream control fails closed");

        new_client(&id);
        in.p = in.end = in.data = empty; in.size = 0;
        CHECK(scard_function_get_status_change_return((void *)(tintptr)id, &in, 0, 0) == 1,
              "F3: empty stream get_status_change fails closed");

        pt = (struct pcsc_transmit *)g_malloc(sizeof(struct pcsc_transmit), 1);
        new_client(&id); pt->uds_client_id = id; pt->cbRecvLength = 0;
        in.p = in.end = in.data = empty; in.size = 0;
        CHECK(scard_function_transmit_return((void *)pt, &in, 0, 0) == 1,
              "F3: empty stream transmit fails closed");

        ps = (struct pcsc_status *)g_malloc(sizeof(struct pcsc_status), 1);
        new_client(&id); ps->uds_client_id = id; ps->cchReaderLen = 0;
        in.p = in.end = in.data = empty; in.size = 0;
        CHECK(scard_function_status_return((void *)ps, &in, 0, 0) == 1,
              "F3: empty stream status fails closed");

        pl = (struct pcsc_list_readers *)g_malloc(sizeof(struct pcsc_list_readers), 1);
        new_client(&id); pl->uds_client_id = id; pl->cchReaders = 1;
        in.p = in.end = in.data = empty; in.size = 0;
        CHECK(scard_function_list_readers_return((void *)pl, &in, 0, 0) == 1,
              "F3: empty stream list_readers fails closed");
    }

    /* status != 0 (card error) short-circuits parsing safely for all. */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 0);
    in_from_bb(&in, &b);
    CHECK(scard_function_get_status_change_return((void *)(tintptr)id, &in, 0, 0x80100002) == 0,
          "error status get_status_change returns cleanly without parsing");
}

/* ================================================================== */
/* Request side: the PC/SC socket message parsers (scard_process_*)     */
/* reached via the transport dispatcher scard_process_msg().            */
/* ================================================================== */
static void
test_request_parsers(void)
{
    struct bb b;
    struct stream in;
    int id;

    printf("[transport: request parsers via scard_process_msg]\n");

    /* ESTABLISH_CONTEXT (0x01): body is dwScope (4 bytes). con->callback_data
     * is set to the client by create_uds_client(). */
    new_client(&id);
    bb_reset(&b); bb_u32(&b, 0x02);      /* dwScope */
    in_from_bb(&in, &b);
    CHECK(scard_process_msg(g_con, &in, 0x01) == 0,
          "process ESTABLISH_CONTEXT ok");

    /* Unknown command must fail closed (rv=1), not crash. */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 4);
    in_from_bb(&in, &b);
    CHECK(scard_process_msg(g_con, &in, 0x9999) == 1,
          "process unknown command fails closed");

    /* Truncated bodies must not read out of bounds (ASan enforces). These
     * exercise the request parsers with short input; we assert only that the
     * call completes without a sanitizer abort. */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 3);
    in_from_bb(&in, &b);
    (void) scard_process_msg(g_con, &in, 0x09);   /* TRANSMIT, short */
    new_client(&id);
    bb_reset(&b); bb_zeros(&b, 2);
    in_from_bb(&in, &b);
    (void) scard_process_msg(g_con, &in, 0x04);   /* CONNECT, short */
    new_client(&id);
    bb_reset(&b);
    in_from_bb(&in, &b);
    (void) scard_process_msg(g_con, &in, 0x0B);   /* STATUS, empty */
    CHECK(1, "process truncated TRANSMIT/CONNECT/STATUS did not crash");
}

static void
put_u32le(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char) v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

/* ================================================================== */
/* Socket handoff: the real $HOME/.pcsc<display>/pcscd.comm UNIX socket */
/* end to end — init, 0700 perms, connect, accept, framed dispatch.     */
/* ================================================================== */
static void
test_socket_handoff(void)
{
    char tmpl[] = "/tmp/scard_test_XXXXXX";
    char *home;
    struct stat st;
    struct sockaddr_un sa;
    struct pcsc_uds_client *uc;
    const char *ipc_path;
    unsigned char msg[12];
    int cs;

    printf("[transport: PC/SC UNIX socket handoff]\n");

    home = mkdtemp(tmpl);
    if (home == NULL) { CHECK(0, "mkdtemp"); return; }
    setenv("HOME", home, 1);

    /* init creates $HOME/.pcsc<display>/ (0700) and listens on pcscd.comm */
    CHECK(scard_pcsc_init() == 0, "scard_pcsc_init sets up the listener");
    CHECK(g_pcsclite_ipc_dir[0] != 0 && g_directory_exist(g_pcsclite_ipc_dir),
          "pcsc IPC directory created");
    if (stat(g_pcsclite_ipc_dir, &st) == 0)
    {
        CHECK((st.st_mode & 0777) == 0700,
              "pcsc IPC directory is mode 0700 (session-private)");
    }
    else
    {
        CHECK(0, "stat pcsc IPC dir");
    }

    /* a session app connects to the redirected pcsc socket */
    cs = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(cs >= 0, "client socket");
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    ipc_path = g_pcsclite_ipc_file;
    /* g_snprintf is a real function call (not the fortify macro), so the
     * char[256] source does not trip -Wformat-truncation into sun_path[108]. */
    g_snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", ipc_path);
    CHECK(connect(cs, (struct sockaddr *)&sa, sizeof(sa)) == 0,
          "client connects to pcscd.comm");

    /* pump the listener: accept -> my_pcsc_trans_conn_in registers a client */
    trans_check_wait_objs(g_lis);
    CHECK(g_uds_clients != NULL && g_uds_clients->count >= 1,
          "server accepted the connection and registered a client");
    uc = (struct pcsc_uds_client *)
         list_get_item(g_uds_clients, g_uds_clients->count - 1);

    /* send a framed ESTABLISH_CONTEXT: [size=4][command=0x01][dwScope=0] */
    put_u32le(msg + 0, 4);       /* size (body length, excludes 8-byte header) */
    put_u32le(msg + 4, 0x01);    /* command */
    put_u32le(msg + 8, 0);       /* dwScope */
    CHECK(write(cs, msg, sizeof(msg)) == (ssize_t) sizeof(msg),
          "client sends framed ESTABLISH_CONTEXT");

    /* pump the accepted connection: header -> data_in -> force_read body ->
     * scard_process_msg -> scard_process_establish_context (send stubbed) */
    CHECK(trans_check_wait_objs(uc->con) == 0,
          "server frames and dispatches the request without error");

    close(cs);
    scard_pcsc_deinit();
    CHECK(g_lis == NULL, "scard_pcsc_deinit tears down the listener");
    rmdir(home);
}

int
main(void)
{
    printf("== MS-RDPESC smart-card response parser tests ==\n");
    g_con = trans_create(TRANS_MODE_UNIX, 8192, 8192);
    if (g_con == NULL) { printf("  FAIL: trans_create\n"); return 2; }
    g_con->trans_send = fake_trans_send;
    g_con->status = TRANS_STATUS_UP;

    test_positive();
    test_security();
    test_request_parsers();
    test_socket_handoff();
    printf("== %d checks, %d failures ==\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
