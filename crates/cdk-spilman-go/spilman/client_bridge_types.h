#ifndef CLIENT_BRIDGE_TYPES_H
#define CLIENT_BRIDGE_TYPES_H

#include <stdint.h>

typedef struct {
    void* user_data;
    int (*call_mint_swap)(void*, const char*, const char*, char**);
    void (*save_channel)(void*, const char*, const char*);
    char* (*get_channel)(void*, const char*);
    char* (*list_channel_ids)(void*);
    void (*delete_channel)(void*, const char*);
    int (*sign_with_tweaked_key)(void*, const char*, const char*, const char*, char**);
} SpilmanClientHostCallbacks;

#endif
