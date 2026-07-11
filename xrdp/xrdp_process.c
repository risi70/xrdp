/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2014
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * main rdp process
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "xrdp.h"

#if defined(ENABLE_BROKER_AUTH)
#include "rdsaad.h"
#include "scp.h"
#include "string_calls.h"
#endif


#if defined(ENABLE_BROKER_AUTH)
static void
secure_erase_bytes(char *data, size_t length)
{
    volatile char *p = data;
    while (length-- > 0)
    {
        *p++ = 0;
    }
}
#endif

static int g_session_id = 0;


#if defined(ENABLE_BROKER_AUTH)
static void
xrdp_process_get_sesman_port(char *port, int port_bytes)
{
    int fd;
    int index;
    char cfg_file[256];
    struct list *names;
    struct list *values;

    strlcpy(port, "3350", port_bytes);
    g_snprintf(cfg_file, sizeof(cfg_file), "%s/sesman.ini", XRDP_CFG_PATH);
    fd = g_file_open_ro(cfg_file);
    if (fd < 0)
    {
        return;
    }

    names = list_create();
    values = list_create();
    names->auto_free = 1;
    values->auto_free = 1;
    if (file_read_section(fd, "Globals", names, values) == 0)
    {
        for (index = 0; index < names->count; ++index)
        {
            const char *name = (const char *)list_get_item(names, index);
            const char *value = (const char *)list_get_item(values, index);
            int port_value;

            if (name != NULL && value != NULL &&
                    g_strcasecmp(name, "ListenPort") == 0)
            {
                port_value = g_atoi(value);
                if (port_value > 0 && port_value < 65000)
                {
                    strlcpy(port, value, port_bytes);
                }
                break;
            }
        }
    }
    list_delete(names);
    list_delete(values);
    g_file_close(fd);
}

int
xrdp_process_rdsaad_preauth(struct xrdp_process *self,
                            const struct xrdp_rdsaad_preauth_request *request,
                            struct xrdp_rdsaad_preauth_response *response)
{
    struct trans *sesman_trans;
    char port[128];
    unsigned char correlation_id[SCP_BAF_CORRELATION_ID_BYTES];
    enum scp_login_status login_result;
    int server_closed;
    int uid;
    int rv = 1;

    if (self == NULL || request == NULL || response == NULL ||
            request->assertion == NULL || request->assertion_length == 0 ||
            request->assertion_length > RDSAAD_MAX_ASSERTION_BYTES ||
            (request->credential_kind == XRDP_BROKER_CREDENTIAL_HANDLE &&
             request->assertion_length != SCP_BROKER_HANDLE_TEXT_LENGTH) ||
            (request->credential_kind != XRDP_BROKER_CREDENTIAL_ASSERTION &&
             request->credential_kind != XRDP_BROKER_CREDENTIAL_HANDLE) ||
            self->baf_preauth_authorized)
    {
        if (response != NULL)
        {
            response->status = XRDP_RDSAAD_PREAUTH_MALFORMED;
        }
        return 1;
    }

    g_random((char *)correlation_id, sizeof(correlation_id));
    xrdp_process_get_sesman_port(port, sizeof(port));
    sesman_trans = scp_connect(port, "xrdp-rdsaad", g_is_term);
    if (sesman_trans == NULL)
    {
        response->status = XRDP_RDSAAD_PREAUTH_SERVICE_UNAVAILABLE;
        return 1;
    }

    if (scp_send_broker_login_request_v1(sesman_trans, 1,
                                         (unsigned short)request->credential_kind,
                                         request->assertion,
                                         request->assertion_length,
                                         request->client_address,
                                         request->server_nonce,
                                         correlation_id) != 0 ||
            scp_msg_in_wait_available(sesman_trans) != 0 ||
            scp_msg_in_get_msgno(sesman_trans) != E_SCP_LOGIN_RESPONSE ||
            scp_get_login_response(sesman_trans, &login_result,
                                   &server_closed, &uid) != 0)
    {
        response->status = XRDP_RDSAAD_PREAUTH_INTERNAL_ERROR;
        goto out;
    }

    if (login_result != E_SCP_LOGIN_OK)
    {
        response->status = XRDP_RDSAAD_PREAUTH_DENIED;
        goto out;
    }

    self->baf_preauth_sesman_trans = sesman_trans;
    self->baf_preauth_uid = uid;
    self->baf_preauth_authorized = 1;
    response->status = XRDP_RDSAAD_PREAUTH_AUTHORIZED;
    response->uid = (int)uid;
    rv = 0;
    sesman_trans = NULL;

out:
    trans_delete(sesman_trans);
    secure_erase_bytes((char *)correlation_id, sizeof(correlation_id));
    return rv;
}
#endif

/*****************************************************************************/
/* always called from xrdp_listen thread */
struct xrdp_process *
xrdp_process_create(struct xrdp_listen *owner, tbus done_event)
{
    struct xrdp_process *self;
    char event_name[256];
    int pid;

    self = (struct xrdp_process *)g_malloc(sizeof(struct xrdp_process), 1);
    self->lis_layer = owner;
    self->done_event = done_event;
    g_session_id++;
    self->session_id = g_session_id;
    pid = g_getpid();
    g_snprintf(event_name, 255, "xrdp_%8.8x_process_self_term_event_%8.8x",
               pid, self->session_id);
    self->self_term_event = g_create_wait_obj(event_name);
    return self;
}

/*****************************************************************************/
void
xrdp_process_delete(struct xrdp_process *self)
{
    if (self == 0)
    {
        return;
    }

    g_delete_wait_obj(self->self_term_event);
    libxrdp_exit(self->session);
    xrdp_wm_delete(self->wm);
    #if defined(ENABLE_BROKER_AUTH)
    trans_delete(self->baf_preauth_sesman_trans);
#endif
    trans_delete(self->server_trans);
    g_free(self);
}

/*****************************************************************************/
static int
xrdp_process_loop(struct xrdp_process *self, struct stream *s)
{
    int rv;

    rv = 0;

    if (self->session != 0)
    {
        rv = libxrdp_process_data(self->session, s);

        if ((self->wm == 0) && (self->session->up_and_running) && (rv == 0))
        {
            LOG_DEVEL(LOG_LEVEL_TRACE, "calling xrdp_wm_init and creating wm");
            self->wm = xrdp_wm_create(self, self->session->client_info);
            /* at this point the wm(window manager) is created and
               wm::login_state is WMLS_RESET and wm::login_state_event is set
               so xrdp_wm_init should be called by xrdp_wm_check_wait_objs
               */
        }
    }

    return rv;
}

/*****************************************************************************/
/* returns boolean */
/* this is so libxrdp.so can known when to quit looping */
static int
xrdp_is_term(void)
{
    return g_is_term();
}

/*****************************************************************************/
static int
xrdp_process_mod_end(struct xrdp_process *self)
{
    if (self->wm != 0)
    {
        if (self->wm->mm != 0)
        {
            if (self->wm->mm->mod != 0)
            {
                if (self->wm->mm->mod->mod_end != 0)
                {
                    return self->wm->mm->mod->mod_end(self->wm->mm->mod);
                }
            }
        }
    }

    return 0;
}

/*****************************************************************************/
static int
xrdp_process_data_in(struct trans *self)
{
    struct xrdp_process *pro;
    struct stream *s;
    int len;

    LOG_DEVEL(LOG_LEVEL_TRACE, "xrdp_process_data_in");
    pro = (struct xrdp_process *)(self->callback_data);

    s = pro->server_trans->in_s;
    switch (pro->server_trans->extra_flags)
    {
        case 0:
            /* early in connection sequence, we're in this mode */
            if (xrdp_process_loop(pro, 0) != 0)
            {
                LOG(LOG_LEVEL_ERROR, "xrdp_process_data_in: "
                    "xrdp_process_loop failed");
                return 1;
            }
            if (pro->session->up_and_running)
            {
                pro->server_trans->header_size = 2;
                pro->server_trans->extra_flags = 1;
                init_stream(s, 0);
            }
            break;

        case 1:
            /* we got 2 bytes */
            if (s->p[0] == 3)
            {
                pro->server_trans->header_size = 4;
                pro->server_trans->extra_flags = 2;
            }
            else
            {
                if (s->p[1] & 0x80)
                {
                    pro->server_trans->header_size = 3;
                    pro->server_trans->extra_flags = 2;
                }
                else
                {
                    len = (tui8)(s->p[1]);
                    pro->server_trans->header_size = len;
                    pro->server_trans->extra_flags = 3;
                }
            }

            len = (int) (s->end - s->data);
            if (pro->server_trans->header_size > (unsigned int)len)
            {
                /* not enough data read yet */
                break;
            }
        /* FALLTHROUGH */

        case 2:
            /* we have enough now to get the PDU bytes */
            len = libxrdp_get_pdu_bytes(s->p);
            if (len == -1)
            {
                LOG(LOG_LEVEL_ERROR, "xrdp_process_data_in: "
                    "xrdp_process_get_packet_bytes failed");
                return 1;
            }
            pro->server_trans->header_size = len;
            pro->server_trans->extra_flags = 3;

            len = (int) (s->end - s->data);
            if (pro->server_trans->header_size > (unsigned int)len)
            {
                /* not enough data read yet */
                break;
            }
        /* FALLTHROUGH */

        case 3:
            /* the whole PDU is read in now process */
            s->p = s->data;
            if (xrdp_process_loop(pro, s) != 0)
            {
                LOG(LOG_LEVEL_ERROR, "xrdp_process_data_in: "
                    "xrdp_process_loop failed");
                return 1;
            }
            init_stream(s, 0);
            pro->server_trans->header_size = 2;
            pro->server_trans->extra_flags = 1;
            break;
    }
    return 0;
}

/*****************************************************************************/
int
xrdp_process_main_loop(struct xrdp_process *self)
{
    int robjs_count;
    int wobjs_count;
    int cont;
    int timeout;
    tbus robjs[32];
    tbus wobjs[32];
    tbus term_obj;

    LOG_DEVEL(LOG_LEVEL_TRACE, "xrdp_process_main_loop");
    self->status = 1;
    self->server_trans->extra_flags = 0;
    self->server_trans->header_size = 0;
    self->server_trans->no_stream_init_on_data_in = 1;
    self->server_trans->trans_data_in = xrdp_process_data_in;
    self->server_trans->callback_data = self;
    init_stream(self->server_trans->in_s, 8192 * 4);
    self->session = libxrdp_init(self, self->server_trans,
                                 self->lis_layer->startup_params->xrdp_ini);
    self->server_trans->si = &(self->session->si);
    self->server_trans->my_source = XRDP_SOURCE_CLIENT;
    /* this callback function is in xrdp_wm.c */
    self->session->callback = callback;
    /* this function is just above */
    self->session->is_term = xrdp_is_term;

    if (libxrdp_process_incoming(self->session) == 0)
    {
        init_stream(self->server_trans->in_s, 32 * 1024);

        term_obj = g_get_term();
        cont = 1;

        while (cont)
        {
            /* build the wait obj list */
            timeout = -1;
            robjs_count = 0;
            wobjs_count = 0;
            robjs[robjs_count++] = term_obj;
            robjs[robjs_count++] = self->self_term_event;
            xrdp_wm_get_wait_objs(self->wm, robjs, &robjs_count,
                                  wobjs, &wobjs_count, &timeout);
            trans_get_wait_objs_rw(self->server_trans, robjs, &robjs_count,
                                   wobjs, &wobjs_count, &timeout);
            /* wait */
            if (g_obj_wait(robjs, robjs_count, wobjs, wobjs_count, timeout) != 0)
            {
                /* error, should not get here */
                g_sleep(100);
            }

            if (g_is_wait_obj_set(term_obj)) /* term */
            {
                LOG(LOG_LEVEL_DEBUG,
                    "Received termination signal, stopping the client message "
                    "processor thread");
                break;
            }

            if (g_is_wait_obj_set(self->self_term_event))
            {
                break;
            }

            if (xrdp_wm_check_wait_objs(self->wm) != 0)
            {
                break;
            }

            if (trans_check_wait_objs(self->server_trans) != 0)
            {
                break;
            }
        }
        /* send disconnect message if possible */
        libxrdp_disconnect(self->session, self->errinfo);
    }
    else
    {
        LOG(LOG_LEVEL_ERROR, "xrdp_process_main_loop: libxrdp_process_incoming failed");
        /* this will try to send a disconnect,
           maybe should check that connection got far enough */
        libxrdp_disconnect(self->session, self->errinfo);
    }
    /* Run end in module */
    xrdp_process_mod_end(self);
    xrdp_wm_delete(self->wm);
    self->wm = NULL;
    libxrdp_exit(self->session);
    self->session = 0;
    self->status = -1;
    g_set_wait_obj(self->done_event);
    return 0;
}
