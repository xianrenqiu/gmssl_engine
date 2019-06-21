#include <stdio.h>
#include <stdlib.h>

#include "pkey.h"
#include "cipher.h"
#include "engine.h"

const char *engine_id = "libgmssl_engine";
const char *engine_name = "Reference implementation of gmssl crypto engine";

#define GMSSL_CMD_INIT_ENGINE (ENGINE_CMD_BASE)
static const ENGINE_CMD_DEFN cmd_defns[] = {
    {GMSSL_CMD_INIT_ENGINE,
     "init engine",
     "init the engine if not already initialized",
     ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}};

static int engine_init(ENGINE *e)
{
    return 1;
}

static int engine_finish(ENGINE *e)
{
    return 1;
}

static int engine_destroy(ENGINE *e)
{
    return 1;
}

static int engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    int ret = 0;

    switch (cmd)
    {
        case GMSSL_CMD_INIT_ENGINE:
            _assert((ret = engine_init(e)) != 0, ret);
        break;

        default:
        break;
    }

    return ret;
}

static int bind_gmssl_engine(ENGINE *e, const char *id)
{
    int ret = 1;

    gmssl_engine_create_ciphers();
    ret &= ENGINE_set_id(e, engine_id);
    ret &= ENGINE_set_name(e, engine_name);
    ret &= ENGINE_set_ciphers(e, gmssl_engine_ciphers);
    ret &= ENGINE_set_pkey_meths(e, gmssl_engine_pkey);
    ret &= ENGINE_set_destroy_function(e, engine_destroy);
    ret &= ENGINE_set_init_function(e, engine_init);
    ret &= ENGINE_set_finish_function(e, engine_finish);
    ret &= ENGINE_set_ctrl_function(e, engine_ctrl);
    ret &= ENGINE_set_cmd_defns(e, cmd_defns);

    _assert(ret != 0, ret);

    return ret;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_gmssl_engine)
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif
