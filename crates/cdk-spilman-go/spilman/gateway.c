#include <stdint.h>
#include <stdlib.h>

typedef struct {
    char* data;
    char* error;
} CResult;

typedef struct {
    void* user_data;
    int (*receiver_key_is_acceptable)(void*, const char*);
    int (*mint_and_keyset_is_acceptable)(void*, const char*, const char*);
    int (*get_funding_and_params)(void*, const char*, char**, char**, char**, char**);
    void (*save_funding)(void*, const char*, const char*, const char*, const char*, const char*);
    uint64_t (*get_amount_due)(void*, const char*, const char*);
    void (*record_payment)(void*, const char*, uint64_t, const char*, const char*);
    int (*is_closed)(void*, const char*);
    char* (*get_server_config)(void*);
    uint64_t (*now_seconds)(void*);
    int (*get_largest_balance_with_signature)(void*, const char*, uint64_t*, char**);
    char* (*get_active_keyset_ids)(void*, const char*, const char*);
    char* (*get_keyset_info)(void*, const char*, const char*);
} SpilmanHostCallbacks;

// Go exports
extern int go_receiver_key_is_acceptable(void*, const char*);
extern int go_mint_and_keyset_is_acceptable(void*, const char*, const char*);
extern int go_get_funding_and_params(void*, const char*, char**, char**, char**, char**);
extern void go_save_funding(void*, const char*, const char*, const char*, const char*, const char*);
extern uint64_t go_get_amount_due(void*, const char*, const char*);
extern void go_record_payment(void*, const char*, uint64_t, const char*, const char*);
extern int go_is_closed(void*, const char*);
extern char* go_get_server_config(void*);
extern uint64_t go_now_seconds(void*);
extern int go_get_largest_balance_with_signature(void*, const char*, uint64_t*, char**);
extern char* go_get_active_keyset_ids(void*, const char*, const char*);
extern char* go_get_keyset_info(void*, const char*, const char*);

SpilmanHostCallbacks fill_callbacks(void* user_data) {
    SpilmanHostCallbacks cb;
    cb.user_data = user_data;
    cb.receiver_key_is_acceptable = go_receiver_key_is_acceptable;
    cb.mint_and_keyset_is_acceptable = go_mint_and_keyset_is_acceptable;
    cb.get_funding_and_params = go_get_funding_and_params;
    cb.save_funding = go_save_funding;
    cb.get_amount_due = go_get_amount_due;
    cb.record_payment = go_record_payment;
    cb.is_closed = go_is_closed;
    cb.get_server_config = go_get_server_config;
    cb.now_seconds = go_now_seconds;
    cb.get_largest_balance_with_signature = go_get_largest_balance_with_signature;
    cb.get_active_keyset_ids = go_get_active_keyset_ids;
    cb.get_keyset_info = go_get_keyset_info;
    return cb;
}
