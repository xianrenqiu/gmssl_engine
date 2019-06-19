#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/eventfd.h>

#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

#include "pkey.h"
#include "cipher.h"
#include "engine.h"

const char *engine_id = "libgmssl_engine";
const char *engine_name = "Reference implementation of gmssl crypto engine";

int engine_init(ENGINE *e)
{
    printf("GmSSL Engine initialization:\n");

    return 1;
}

#define GMSSL_CMD_INIT_ENGINE (ENGINE_CMD_BASE)
static const ENGINE_CMD_DEFN cmd_defns[] = {
    {GMSSL_CMD_INIT_ENGINE,
     "INIT_ENGINE",
     "Initializes the engine if not already initialized",
     ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}};

static int engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    uint32_t retVal = 0;

    switch (cmd)
    {
    case GMSSL_CMD_INIT_ENGINE:
        printf("Init engine\n");
        if ((retVal = engine_init(e)) == 0)
        {
            printf("Failure initializing engine\n");
        }
        break;

    default:
        break;
    }

    return retVal;
}

static int engine_finish(ENGINE *e)
{
    return 1;
}

static int engine_destroy(ENGINE *e)
{
    printf("---- Destroying Engine...\n\n");
    return 1;
}

static int bind_gmssl_engine(ENGINE *e, const char *id)
{
    int ret = 0;
    printf("Bind gmssl_engine.\n");

    gmssl_engine_create_ciphers();

    if (id && (strcmp(id, engine_id) != 0))
    {
        printf("ENGINE_id defined already!\n");
        goto end;
    }

    if (!ENGINE_set_id(e, engine_id))
    {
        printf("ENGINE_set_id failed\n");
        goto end;
    }

    if (!ENGINE_set_name(e, engine_name))
    {
        printf("ENGINE_set_name failed\n");
        goto end;
    }

    if (!ENGINE_set_ciphers(e, gmssl_engine_ciphers)) {
        printf("ENGINE_set_ciphers failed\n");
        goto end;
    }
    
    if (!ENGINE_set_pkey_meths(e, gmssl_engine_pkey)) {
        printf("ENGINE_set_pkey_meths failed\n");
        goto end;
    }

    ret = 1;
    ret &= ENGINE_set_destroy_function(e, engine_destroy);
    ret &= ENGINE_set_init_function(e, engine_init);
    ret &= ENGINE_set_finish_function(e, engine_finish);
    ret &= ENGINE_set_ctrl_function(e, engine_ctrl);
    ret &= ENGINE_set_cmd_defns(e, cmd_defns);
    if (ret == 0)
        printf("Engine failed to register init, finish or destroy functions\n");

end:
    return ret;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_gmssl_engine)
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif
