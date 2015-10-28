/*
 *  This file implement coap forward proxy
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "coap.h"
#include "proxy.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static size_t
address_to_string(const struct coap_address_t *addr, unsigned char *buf, size_t len)
{
#ifdef HAVE_ARPA_INET_H
    const void *addrptr = NULL;
    in_port_t port;
    unsigned char *p = buf;

    switch (addr->addr.sa.sa_family)
    {
    case AF_INET:
        addrptr = &addr->addr.sin.sin_addr;
        port = ntohs(addr->addr.sin.sin_port);
        break;
    case AF_INET6:
        if (len < 7) /* do not proceed if buffer is even too short for [::]:0 */
            return 0;

        addrptr = &addr->addr.sin6.sin6_addr;
        port = ntohs(addr->addr.sin6.sin6_port);

        break;
    default:
        memcpy(buf, "(unknown address type)", min(22, len));
        return min(22, len);
    }

    if (inet_ntop(addr->addr.sa.sa_family, addrptr, (char *)p, len) == 0)
    {
        perror("coap_print_addr");
        return 0;
    }

    p += strnlen((char *)p, len);

    if (addr->addr.sa.sa_family == AF_INET6)
    {
        if (p < buf + len)
        {
        }
        else
            return 0;
    }

    p += snprintf((char *)p, buf + len - p + 1, ":%d", port);

    return buf + len - p;
#else /* HAVE_ARPA_INET_H */
# if WITH_CONTIKI
    unsigned char *p = buf;
    uint8_t i;
#  if WITH_UIP6
    const unsigned char hex[] = "0123456789ABCDEF";

    if (len < 41)
        return 0;

    *p++ = '[';

    for (i=0; i < 16; i += 2)
    {
        if (i)
        {
            *p++ = ':';
        }
        *p++ = hex[(addr->addr.u8[i] & 0xf0) >> 4];
        *p++ = hex[(addr->addr.u8[i] & 0x0f)];
        *p++ = hex[(addr->addr.u8[i+1] & 0xf0) >> 4];
        *p++ = hex[(addr->addr.u8[i+1] & 0x0f)];
    }
    *p++ = ']';
#  else /* WITH_UIP6 */
#   warning "IPv4 network addresses will not be included in debug output"

    if (len < 21)
        return 0;
#  endif /* WITH_UIP6 */
    if (buf + len - p < 6)
        return 0;

#ifdef HAVE_SNPRINTF
    p += snprintf((char *)p, buf + len - p + 1, ":%d", uip_htons(addr->port));
#else /* HAVE_SNPRINTF */
    /* @todo manual conversion of port number */
#endif /* HAVE_SNPRINTF */

    return p - buf;
# else /* WITH_CONTIKI */
    /* TODO: output addresses manually */
#   warning "inet_ntop() not available, network addresses will not be included in debug output"
# endif /* WITH_CONTIKI */
    return 0;
#endif
}


static int
check_token(coap_pdu_t *pdu)
{
    if ( pdu && pdu->hdr->token_length > 0)
    {
        return 1;
    }

    return 0;
}

static int
accept_poxy_request(coap_context_t *context, coap_queue_t *rcvd)
{
    if (context == 0 || rcvd == 0)
    {
        return 0;
    }

    /*check if is it have token*/
    if ( check_token(rcvd->pdu) == 0 )
    {
        coap_opt_filter_t ft;
        coap_send_error(context,
                        rcvd->pdu,
                        &rcvd->remote,
                        COAP_RESPONSE_400,
                        ft);

        warn("proxy recv a message that have not a token\n");
        return 0;
    }
    else if (rcvd->pdu->hdr->type == COAP_MESSAGE_CON )
    {
        coap_send_ack(context, &rcvd->remote, rcvd->pdu);
    }

    return 1;
}

static int
order_opts(void *a, void *b)
{
    if (!a || !b)
        return a < b ? -1 : 1;

    if (COAP_OPTION_KEY(*(coap_option *)a) < COAP_OPTION_KEY(*(coap_option *)b))
        return -1;

    return COAP_OPTION_KEY(*(coap_option *)a) == COAP_OPTION_KEY(*(coap_option *)b);
}

static coap_list_t *
new_option_node(unsigned short key, unsigned int length, unsigned char *data)
{
    coap_option *option;
    coap_list_t *node;

    option = coap_malloc(sizeof(coap_option) + length);
    if ( !option )
        goto error;

    COAP_OPTION_KEY(*option) = key;
    COAP_OPTION_LENGTH(*option) = length;
    memcpy(COAP_OPTION_DATA(*option), data, length);

    /* we can pass NULL here as delete function since option is released automatically  */
    node = coap_new_listnode(option, NULL);

    if ( node )
        return node;

error:
    warn("new_option_node: malloc\n");
    coap_free( option );
    return NULL;
}

static int
add_src_opt_to_request(coap_list_t * opt_list, coap_pdu_t * from)
{
    coap_opt_iterator_t opt_iter;
    coap_opt_t *option;

    /* show options, if any */
    coap_option_iterator_init((coap_pdu_t *)from, &opt_iter, COAP_OPT_ALL);

    while ((option = coap_option_next(&opt_iter)))
    {
        if (opt_iter.type == COAP_OPTION_URI_PATH ||
                opt_iter.type == COAP_OPTION_PROXY_URI ||
                opt_iter.type == COAP_OPTION_URI_HOST ||
                opt_iter.type == COAP_OPTION_LOCATION_PATH ||
                opt_iter.type == COAP_OPTION_LOCATION_QUERY ||
                opt_iter.type == COAP_OPTION_URI_PATH ||
                opt_iter.type == COAP_OPTION_BLOCK1 ||
                opt_iter.type == COAP_OPTION_BLOCK2 ||
                opt_iter.type == COAP_OPTION_URI_QUERY)
        {
            continue;
        }
        else
        {
            coap_insert(&opt_list,
                        new_option_node(opt_iter.type,
                                        COAP_OPT_LENGTH(option),
                                        COAP_OPT_VALUE(option)),
                        order_opts);
        }
    }

    return 1;
}


static int
insert_opt_to_request(coap_pdu_t * pdu, coap_opt_t *proxy_uri_opt, coap_pdu_t *src)
{
    unsigned char portbuf[2];
#define BUFSIZE 40
    unsigned char _buf[BUFSIZE];
    unsigned char *buf = _buf;
    size_t buflen;
    int res;
    coap_list_t *optlist = NULL;
    coap_list_t *opt;
    coap_uri_t uri;

    memset(portbuf, 0, sizeof(portbuf));
    memset(_buf, 0, BUFSIZE);

    coap_split_uri((unsigned char *)COAP_OPT_VALUE(proxy_uri_opt),
                   COAP_OPT_LENGTH(proxy_uri_opt),
                   &uri );

    if (uri.port != COAP_DEFAULT_PORT)
    {
        coap_insert( &optlist,
                     new_option_node(COAP_OPTION_URI_PORT,
                                     coap_encode_var_bytes(portbuf, uri.port),
                                     portbuf),
                     order_opts);
    }

    if (uri.host.s != 0)
    {
        coap_insert( &optlist,
                     new_option_node(COAP_OPTION_URI_HOST,
                                     uri.host.length,
                                     uri.host.s),
                     order_opts);

    }
    
    if (uri.path.length)
    {
        buflen = BUFSIZE;
        res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);

        while (res--)
        {
            coap_insert(&optlist,
                        new_option_node(COAP_OPTION_URI_PATH,
                                        COAP_OPT_LENGTH(buf),
                                        COAP_OPT_VALUE(buf)),
                        order_opts);

            buf += COAP_OPT_SIZE(buf);
        }
    }
    
    if (uri.query.length)
    {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);

        while (res--)
        {
            coap_insert(&optlist, new_option_node(COAP_OPTION_URI_QUERY,
                                                  COAP_OPT_LENGTH(buf),
                                                  COAP_OPT_VALUE(buf)),
                        order_opts);

            buf += COAP_OPT_SIZE(buf);
        }
    }

    add_src_opt_to_request(optlist, src);

    for (opt = optlist; opt; opt = opt->next)
    {
        coap_add_option(pdu, COAP_OPTION_KEY(*(coap_option *)opt->data),
                        COAP_OPTION_LENGTH(*(coap_option *)opt->data),
                        COAP_OPTION_DATA(*(coap_option *)opt->data));
    }

    coap_delete_list(optlist);

    return 1;

}

static coap_pdu_t *
create_forward_request( coap_queue_t *rcvd)
{
    coap_pdu_t *outgoing;
    size_t data_len;
    unsigned char *data;
    coap_opt_t *proxy_uri_opt;
    coap_opt_iterator_t opt_iter;

    outgoing = coap_pdu_init(rcvd->pdu->hdr->type,
                             rcvd->pdu->hdr->code,
                             rcvd->pdu->hdr->id,
                             rcvd->pdu->max_size);

    if (outgoing == 0)
    {
        warn("failed to allocate outgoing pdu\n");
        return 0;

    }

    if (coap_add_token(outgoing,
                       rcvd->pdu->hdr->token_length,
                       rcvd->pdu->hdr->token) == 0)
    {
        warn("add token to pdu failed\n");
        return 0;
    }

    proxy_uri_opt = coap_check_option(rcvd->pdu, COAP_OPTION_PROXY_URI, &opt_iter);

    insert_opt_to_request(outgoing, proxy_uri_opt, rcvd->pdu);
    
    if (coap_get_data(rcvd->pdu, &data_len, &data)== 1)
    {
        if (coap_add_data(outgoing, data_len, data) == 0 )
        {
            warn("failed to add data to outgoing pdu\n");

            coap_delete_pdu(outgoing);
            return 0;
        }
    }


    return outgoing;

}

static int
construct_address(str *addr, unsigned int port, coap_address_t *out)
{
    struct addrinfo *res, *ainfo;
    struct addrinfo hints;

    char addrstr[256];
    int error, len=-1;
    
    if( addr == 0 || port == 0 || out == 0)
        return 0;

    coap_address_init(out);

    memset(addrstr, 0, sizeof(addrstr));

    if (addr->length)
        memcpy(addrstr, addr->s, addr->length);
    else
        memcpy(addrstr, "localhost", 9);

    memset ((char *)&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(addrstr, "", &hints, &res);

    if (error != 0)
    {
        return error;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next)
    {
        switch (ainfo->ai_family)
        {
        case AF_INET6:
        case AF_INET:
            len = ainfo->ai_addrlen;
            memcpy(&(out->addr.sa), ainfo->ai_addr, len);
            break;
        default:
            ;
        }
    }

    out->size = len;
    out->addr.sin.sin_port = htons(port);

    freeaddrinfo(res);
    return len;

}

static int get_hdr_and_addr_length(coap_pdu_t* pdu)
{
    info("token_len= %d\n", pdu->hdr->token_length);

    return (sizeof(coap_exchange_info_t) + pdu->hdr->token_length);

}

static void create_token_key(coap_address_t *addr,
                             unsigned char *token,
                             unsigned int len,
                             coap_key_t key)
{
    /* Compare the complete address structure in case of IPv4. For IPv6,
     * we need to look at the transport address only. */

#ifdef WITH_POSIX
    switch (addr->addr.sa.sa_family)
    {
    case AF_INET:
        coap_hash((const unsigned char *)&addr->addr.sa, addr->size, key);
        break;
    case AF_INET6:
        coap_hash((const unsigned char *)&addr->addr.sin6.sin6_port,
                  sizeof(addr->addr.sin6.sin6_port), key);
        coap_hash((const unsigned char *)&addr->addr.sin6.sin6_addr,
                  sizeof(addr->addr.sin6.sin6_addr), key);
        break;
    default:
        return;
    }
#endif

    if (token)
        coap_hash((const unsigned char *)token, len, key);

}

static void dump_map_node_key(coap_address_t *addr, 
                              unsigned char *token,
                              unsigned int len)
{
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif

    unsigned char s_addr[INET6_ADDRSTRLEN+8];
    coap_print_addr(addr, s_addr, INET6_ADDRSTRLEN+8);
    
    info("\n--------------- dump map key node--------------\n");
    info("address:%s\n", s_addr);
    info("token  :[len=%d]%s\n", len, token);
}

static void create_map_node_key(coap_proxy_map_t* node)
{
    coap_address_t *addr;
    coap_hdr_t *hdr;
    unsigned char *token;

    addr = &(node->to_server->source);
    hdr = &(node->to_server->hdr);
    token = node->to_server->token;

    memset(node->key, 0 , sizeof(coap_key_t));

    create_token_key(addr,
                     token,
                     hdr->token_length,
                     node->key);

    dump_map_node_key(addr, token, hdr->token_length);
}

static void add_exchange_info(coap_context_t *context,
                              coap_exchange_info_t *from,
                              coap_exchange_info_t *to)
{
    coap_proxy_map_t *map_node;

    map_node = (coap_proxy_map_t*)coap_malloc(sizeof(coap_proxy_map_t));

    if (map_node)
    {
        map_node->from_client = from;
        map_node->to_server= to;

        create_map_node_key(map_node);

#ifndef WITH_CONTIKI
#ifdef COAP_RESOURCES_NOHASH
        LL_PREPEND(context->proxy_map, map_node);
#else
        HASH_ADD(hh, context->proxy_map, key, sizeof(coap_key_t), map_node);
#endif
#endif /* WITH_CONTIKI */
    }
    else
    {
        warn("map_node not allocated\n");
    }

}

static void cache_exchange_info(coap_context_t *context,
                                coap_pdu_t *server,
                                coap_address_t *server_addr,
                                coap_pdu_t *client,
                                coap_address_t *client_addr)
{

    unsigned char *from_client;
    unsigned char *to_server;
    coap_exchange_info_t *from;
    coap_exchange_info_t *to;

    to_server = coap_malloc(get_hdr_and_addr_length(server));
    from_client = coap_malloc(get_hdr_and_addr_length(client));

    assert(to_server !=0 );
    assert(from_client !=0 );

    to = (coap_exchange_info_t*)to_server;
    from = (coap_exchange_info_t*)from_client;

    to->token = to_server+sizeof(coap_exchange_info_t);
    from->token = from_client+sizeof(coap_exchange_info_t);

    memcpy(&to->hdr, server->hdr, (sizeof(coap_hdr_t)));
    memcpy(&to->source, server_addr, sizeof(coap_address_t));

    if (server->hdr->token_length)
        memcpy(to->token, server->hdr->token, server->hdr->token_length);

    memcpy(&from->hdr, client->hdr, (sizeof(coap_hdr_t)));
    memcpy(&from->source, client_addr, sizeof(coap_address_t));

    if (client->hdr->token_length)
        memcpy(from->token, client->hdr->token, client->hdr->token_length);

    add_exchange_info(context, from, to);

}

static void handle_proxy_request(coap_context_t *context, coap_queue_t *rcvd)
{
    coap_opt_t *proxy_uri_opt, *host, *port;
    coap_opt_iterator_t opt_iter;
    coap_pdu_t *outgoing;
    coap_address_t server;
    str host_s, port_s;
    coap_opt_filter_t ft;
    unsigned int decode_port;

    proxy_uri_opt = coap_check_option(rcvd->pdu, COAP_OPTION_PROXY_URI, &opt_iter);

    /* bad request, send back error ack*/
    if (proxy_uri_opt == 0 )
    {
        info("proxy_uri_opt is null\n");
        goto TO_ERROR2;
    }

    outgoing = create_forward_request( rcvd);

    if (outgoing == 0)
    {
        info("outgoing pdu is null\n");
        goto TO_ERROR2;
    }

    host = coap_check_option(outgoing, COAP_OPTION_URI_HOST,&opt_iter);
    port = coap_check_option(outgoing, COAP_OPTION_URI_PORT,&opt_iter);

    if( host == 0 || port == 0)
    {
        info("host or port of server is null\n");
        goto TO_ERROR;

    }

    host_s.s = coap_opt_value(host);
    host_s.length = coap_opt_length(host);

    port_s.s = coap_opt_value(port);
    port_s.length = coap_opt_length(port);

    decode_port = coap_decode_var_bytes(port_s.s,port_s.length);

    if (construct_address(&host_s, decode_port, &server) < 0 )
    {
        warn("construct server ip failed\n");
        goto TO_ERROR;
    }
    
    cache_exchange_info(context, outgoing, &server, rcvd->pdu, &rcvd->remote);
    
    coap_send_confirmed(context, &server, outgoing);

    return;

TO_ERROR:

    info("delete outgoing at error1 and snd 500 back \n");

    coap_delete_pdu(outgoing);

    coap_send_error(context,
                    rcvd->pdu,
                    &rcvd->remote,
                    COAP_RESPONSE_500,
                    ft);
    return;

TO_ERROR2:

    info("delete outgoing at error2 and snd 500 back \n");

    coap_send_error(context,
                    rcvd->pdu,
                    &rcvd->remote,
                    COAP_RESPONSE_500,
                    ft);
    return;

}

static void get_key_from_response(coap_queue_t *rcvd, coap_key_t key)
{
    coap_address_t *svr_addr;
    coap_hdr_t *hdr;

    svr_addr = &rcvd->remote;
    hdr = rcvd->pdu->hdr;
    
    create_token_key(svr_addr,
                     (unsigned char*)hdr->token,
                     hdr->token_length,
                     key);

    dump_map_node_key(svr_addr, hdr->token,hdr->token_length);
}

static coap_proxy_map_t*
find_proxy_map_node(coap_context_t *context, coap_key_t key)
{
#ifndef WITH_CONTIKI
    coap_proxy_map_t *tmp;
#ifdef COAP_RESOURCES_NOHASH
    tmp = NULL;
    LL_FOREACH(context->proxy_map, tmp)
    {
        /* if you think you can outspart the compiler and speed things up by (eg by
         * casting to uint32* and comparing alues), increment this counter: 1 */
        if (memcmp(key, tmp->key, sizeof(coap_key_t)) == 0)
            return tmp;
    }
    return NULL;
#else
    HASH_FIND(hh, context->proxy_map, key, sizeof(coap_key_t), tmp);

    return tmp;
#endif
#else /* WITH_CONTIKI */

    return NULL;
#endif /* WITH_CONTIKI */
}


static int
remove_prxy_map_node(coap_context_t *context, coap_proxy_map_t *node)
{
    if (!context)
        return 0;

#if defined(WITH_POSIX)
#ifdef COAP_RESOURCES_NOHASH
    LL_DELETE(context->proxy_map, node);
#else
    HASH_DELETE(hh, context->proxy_map, node);
#endif

#ifdef WITH_POSIX
    coap_free(node->from_client);
    coap_free(node->to_server);
    coap_free(node);
#endif
#endif

    return 1;
}


static int
compare_token(coap_exchange_info_t *exchange_node,
              coap_pdu_t *pdu)
{
    coap_hdr_t *src_hdr = &exchange_node->hdr;
    coap_hdr_t *dst_hdr = pdu->hdr;

    if (src_hdr->token_length == dst_hdr->token_length)
    {
        if (memcmp(exchange_node->token, 
                   dst_hdr->token, 
                   src_hdr->token_length) == 0)
        {
            return 1;
        }
    }

    return 0;
    
}

static int
compare_addr(coap_address_t *src, coap_address_t *dst)
{
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    
    unsigned char src_addr[INET6_ADDRSTRLEN+8];
    unsigned char dst_addr[INET6_ADDRSTRLEN+8];

    memset(src_addr, 0, sizeof(src_addr));
    memset(dst_addr, 0, sizeof(dst_addr));
    
    address_to_string(src, src_addr, INET6_ADDRSTRLEN+8);
    address_to_string(dst, dst_addr, INET6_ADDRSTRLEN+8);

    if (strstr((char*)dst_addr, (char*)src_addr) != NULL ||
        strstr((char*)src_addr, (char*)dst_addr) != NULL )
    {
        return 1;
    }

    return 0;
}

static int
compare_exchange_node_by_hard(coap_exchange_info_t *exchange_node,
                              coap_address_t *addr,
                              coap_pdu_t *pdu)
{
    if ((compare_token(exchange_node, pdu)== 1) &&
        (compare_addr(&exchange_node->source, addr) == 1)
        )
    {
        return 1;
    }

    return 0;
}

static coap_proxy_map_t*
find_proxy_map_node_by_hard(coap_context_t *context,
                            coap_address_t *addr, 
                            coap_pdu_t *pdu)
{
#ifndef WITH_CONTIKI
        coap_proxy_map_t *tmp;
        coap_proxy_map_t *rtmp;
#ifdef COAP_RESOURCES_NOHASH
        tmp = NULL;
        LL_FOREACH(context->proxy_map, tmp)
#else
        HASH_ITER(hh, context->proxy_map, tmp, rtmp)
#endif        
        {
            coap_exchange_info_t *exchange_node = tmp->to_server;

            if ( compare_exchange_node_by_hard(exchange_node, addr, pdu) == 1)
            {
                return tmp;
            }
                
        }
        return NULL;
        
#else /* WITH_CONTIKI */
    
        return NULL;
#endif /* WITH_CONTIKI */    
}

static void handle_proxy_response(coap_context_t *context,
                                  coap_queue_t *sent,
                                  coap_queue_t *rcvd)
{
    coap_key_t key;
    coap_proxy_map_t *proxy_map;
    coap_address_t *client_addr;

    if (sent == 0)
    {
    }
    
    get_key_from_response(rcvd, key);

    /* find exchange from proxy map*/
    proxy_map = find_proxy_map_node(context, key);

    /* maybe key is invalid..., so, we should change another method
     *  to find proxy map. 
     */
     if( rcvd && rcvd->pdu )
     {
        proxy_map = find_proxy_map_node_by_hard(context, &rcvd->remote, rcvd->pdu);
     }

    /* if not find exchange node, maybe server occur error,
     * so reply rst message to server
     */
    if (proxy_map == 0 &&
            rcvd->pdu->hdr->type != COAP_MESSAGE_ACK)
    {
        warn("not find exchange node, send back rst message to server\n");

        coap_send_rst(context, &rcvd->remote, rcvd->pdu);

        return;
    }

    if (proxy_map)
    {
        info("snd response to client\n");

        client_addr = &(proxy_map->from_client->source);

        /*forward response to client*/
        coap_send(context, client_addr, rcvd->pdu);

        /*
        *  FIXME : how to handle observe????
        */
        /*remove_prxy_map_node(context, proxy_map);*/
    }
    else
        info("proxy_map == 0, cannt snd response to client\n");

}


void handle_proxy(coap_context_t *context,
                  coap_queue_t *sent,
                  coap_queue_t *rcvd)
{
    if (accept_poxy_request(context, rcvd) == 1)
    {
        if (COAP_MESSAGE_IS_REQUEST(rcvd->pdu->hdr))
        {
            handle_proxy_request(context, rcvd);
        }
        else if (COAP_MESSAGE_IS_RESPONSE(rcvd->pdu->hdr))
        {
            handle_proxy_response(context, sent, rcvd);
        }
        else
        {
            debug("dropped message with invalid code\n");
            coap_send_message_type(context, &rcvd->remote, rcvd->pdu,
                                   COAP_MESSAGE_RST);
        }
    }
}




