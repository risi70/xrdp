/*
 * libFuzzer target for the MS-RDPESC smart-card response parsers in
 * sesman/chansrv/smartcard_pcsc.c (--enable-smartcard).
 *
 * Drives every scard_function_*_return() with attacker-controlled bytes and a
 * fuzzer-selected IOStatus, under ASan/UBSan, so any out-of-bounds read/write
 * or UAF in the [MS-RDPESC] response decode aborts. Complements the
 * deterministic vectors in tests/baf/test_smartcard_scard.c (F1-F9).
 *
 * Not built by normal `make`. Build with Clang/libFuzzer, e.g.:
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *     -I../../.. -I../../../common -I../../../sesman/chansrv \
 *     fuzz_smartcard_scard.c \
 *     ../../../common/os_calls.c ../../../common/parse.c \
 *     ../../../common/string_calls.c ../../../common/list.c \
 *     ../../../common/log.c ../../../common/trans.c \
 *     ../../../common/file.c ../../../common/os_calls_fips.c \
 *     -lpthread -lcrypto -o fuzz_smartcard_scard
 *
 * (link whatever common/*.c your tree needs; simplest is to link libcommon.la.)
 */

#include <config_ac.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "arch.h"
#include "parse.h"
#include "trans.h"
#include "list.h"
#include "smartcard_internal.h"

/* chansrv global referenced by smartcard_pcsc.c's socket setup. */
char g_display_str[256] = "10.0";

/* Send-side lives in smartcard.c (not linked): stub it. */
int scard_send_establish_context(void *u, int s) { (void)u; (void)s; return 0; }
int scard_send_release_context(void *u, char *c, int b) { (void)u; (void)c; (void)b; return 0; }
int scard_send_is_valid_context(void *u, char *c, int b) { (void)u; (void)c; (void)b; return 0; }
int scard_send_list_readers(void *u, char *c, int b, char *g, int n, int w)
{ (void)u; (void)c; (void)b; (void)g; (void)n; (void)w; return 0; }
int scard_send_get_status_change(void *u, char *c, int b, int w, tui32 t, tui32 nr, READER_STATE *r)
{ (void)u; (void)c; (void)b; (void)w; (void)t; (void)nr; (void)r; return 0; }
int scard_send_connect(void *u, char *c, int b, int w, READER_STATE *r)
{ (void)u; (void)c; (void)b; (void)w; (void)r; return 0; }
int scard_send_reconnect(void *u, char *c, int b, char *d, int db, READER_STATE *r)
{ (void)u; (void)c; (void)b; (void)d; (void)db; (void)r; return 0; }
int scard_send_begin_transaction(void *u, char *c, int b, char *d, int db)
{ (void)u; (void)c; (void)b; (void)d; (void)db; return 0; }
int scard_send_end_transaction(void *u, char *c, int b, char *d, int db, tui32 x)
{ (void)u; (void)c; (void)b; (void)d; (void)db; (void)x; return 0; }
int scard_send_status(void *u, int w, char *c, int b, char *d, int db, int rl, int al)
{ (void)u; (void)w; (void)c; (void)b; (void)d; (void)db; (void)rl; (void)al; return 0; }
int scard_send_disconnect(void *u, char *c, int b, char *d, int db, int x)
{ (void)u; (void)c; (void)b; (void)d; (void)db; (void)x; return 0; }
int scard_send_transmit(void *u, char *c, int b, char *d, int db, char *sd, int sb,
                        int rb, struct xrdp_scard_io_request *si, struct xrdp_scard_io_request *ri)
{ (void)u; (void)c; (void)b; (void)d; (void)db; (void)sd; (void)sb; (void)rb; (void)si; (void)ri; return 0; }
int scard_send_control(void *u, char *c, int b, char *d, int db, char *sd, int sb, int rb, int cc)
{ (void)u; (void)c; (void)b; (void)d; (void)db; (void)sd; (void)sb; (void)rb; (void)cc; return 0; }
int scard_send_cancel(void *u, char *c, int b) { (void)u; (void)c; (void)b; return 0; }
int scard_send_get_attrib(void *u, char *card, int b, READER_STATE *r)
{ (void)u; (void)card; (void)b; (void)r; return 0; }

#include "smartcard_pcsc.c"

static struct trans *g_con;

static int
fake_trans_send(struct trans *self, const char *data, int len)
{
    (void)self; (void)data;
    return len;
}

static void
ensure_init(void)
{
    if (g_con == NULL)
    {
        g_con = trans_create(TRANS_MODE_UNIX, 8192, 8192);
        g_con->trans_send = fake_trans_send;
        g_con->status = TRANS_STATUS_UP;
    }
}

static void
drop_client(struct pcsc_uds_client *c)
{
    int index = list_index_of(g_uds_clients, (tintptr) c);
    if (index >= 0)
    {
        list_remove_item(g_uds_clients, index);
    }
    free_uds_client(c);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct stream in;
    struct pcsc_uds_client *c;
    char *buf;
    int id;
    int status;
    unsigned sel;

    ensure_init();
    if (size < 2)
    {
        return 0;
    }
    sel = data[0] % 7;
    status = (data[1] & 1) ? 0 : 0x80100002; /* success vs card error */
    data += 2;
    size -= 2;

    /* Copy into an exact-size heap block so ASan bounds are tight. */
    buf = (char *) malloc(size ? size : 1);
    memcpy(buf, data, size);
    in.data = buf;
    in.p = buf;
    in.end = buf + size;
    in.size = (int) size;
    in.next_packet = NULL;

    c = create_uds_client(g_con);
    if (g_uds_clients == 0)
    {
        g_uds_clients = list_create();
    }
    list_add_item(g_uds_clients, (tintptr) c);
    id = c->uds_client_id;

    switch (sel)
    {
        case 0:
            scard_function_establish_context_return((void *)(tintptr) id, &in, (int) size, status);
            break;
        case 1:
        {
            struct pcsc_transmit *pt = (struct pcsc_transmit *) g_malloc(sizeof(*pt), 1);
            pt->uds_client_id = id;
            pt->cbRecvLength = 0;
            scard_function_transmit_return((void *) pt, &in, (int) size, status);
            break;
        }
        case 2:
            scard_function_control_return((void *)(tintptr) id, &in, (int) size, status);
            break;
        case 3:
        {
            char ctxbuf[] = "ctx";
            c->connect_context = uds_client_add_context(c, ctxbuf, 3);
            scard_function_connect_return((void *)(tintptr) id, &in, (int) size, status);
            break;
        }
        case 4:
            scard_function_get_status_change_return((void *)(tintptr) id, &in, (int) size, status);
            break;
        case 5:
        {
            struct pcsc_status *ps = (struct pcsc_status *) g_malloc(sizeof(*ps), 1);
            ps->uds_client_id = id;
            ps->cchReaderLen = 0;
            scard_function_status_return((void *) ps, &in, (int) size, status);
            break;
        }
        case 6:
        {
            struct pcsc_list_readers *pl = (struct pcsc_list_readers *) g_malloc(sizeof(*pl), 1);
            pl->uds_client_id = id;
            pl->cchReaders = 64;
            scard_function_list_readers_return((void *) pl, &in, (int) size, status);
            break;
        }
    }

    drop_client(c);
    free(buf);
    return 0;
}
