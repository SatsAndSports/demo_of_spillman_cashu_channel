#include "client_bridge_types.h"

// Go exports for client host callbacks
extern int go_client_call_mint_swap(void*, const char*, const char*, char**);
extern void go_client_save_channel(void*, const char*, const char*);
extern char* go_client_get_channel(void*, const char*);
extern char* go_client_list_channel_ids(void*);
extern void go_client_delete_channel(void*, const char*);

SpilmanClientHostCallbacks fill_client_callbacks(void* user_data) {
    SpilmanClientHostCallbacks cb;
    cb.user_data = user_data;
    cb.call_mint_swap = go_client_call_mint_swap;
    cb.save_channel = go_client_save_channel;
    cb.get_channel = go_client_get_channel;
    cb.list_channel_ids = go_client_list_channel_ids;
    cb.delete_channel = go_client_delete_channel;
    return cb;
}
