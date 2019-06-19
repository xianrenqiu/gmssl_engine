#ifndef __ENGINE_H__
#define __ENGINE_H__

#include <openssl/engine.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#if 0
#define DEBUG_FUNC_INFO() ZENGINE_DEBUG("%s()\n", __func__)
#else
#define DEBUG_FUNC_INFO()
#endif

#define _assert(cond, ret)      do { if (!(cond)) { \
                                    printf("assert: '" #cond "' failed [line: %d]\n", __LINE__); \
                                    return ret; \
                                } } while (0)
                                
extern const char *engine_id;
extern const char *engine_name;
int engine_finish_int(ENGINE *e, int reset_globals);

#endif /* __ENGINE_H__ */
