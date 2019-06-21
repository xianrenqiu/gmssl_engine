#ifndef __ENGINE_H__
#define __ENGINE_H__

#define _assert(cond, ret)      do { if (!(cond)) { \
                                    printf("assert: '" #cond "' failed [%s line: %d]\n", __FILE__, __LINE__); \
                                    return ret; \
                                } } while (0)
                               
#endif /* __ENGINE_H__ */
