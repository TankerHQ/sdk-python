typedef struct tanker_future_t tanker_future_t;
typedef struct tanker_future tanker_expected_t;
typedef struct tanker_promise tanker_promise_t;
typedef struct tanker_error tanker_error_t;
typedef struct tanker_admin tanker_admin_t;
typedef char b64char;
typedef struct tanker_trustchain_descriptor
{
  char const* name;
  b64char const* id;
  b64char const* private_key;
  b64char const* public_key;
} tanker_trustchain_descriptor_t;

void tanker_init();

extern "Python" void log_handler(const char* category, char level, const char* message);
extern "Python" void revoke_callback(void* arg, void* data);

typedef void* (*tanker_future_then_t)(tanker_future_t* fut, void* arg);
void tanker_future_wait(tanker_future_t* future);
unsigned char tanker_future_has_error(tanker_future_t* future);
tanker_error_t* tanker_future_get_error(tanker_future_t* future);
void tanker_future_destroy(tanker_future_t* future);
tanker_future_t* tanker_future_then(tanker_future_t* future, tanker_future_then_t cb, void* arg);

enum tanker_error_code
{
  TANKER_ERROR_NO_ERROR,
  TANKER_ERROR_OTHER,
  TANKER_ERROR_INVALID_TANKER_STATUS,
  TANKER_ERROR_SERVER_ERROR,
  TANKER_ERROR_INVALID_ARGUMENT,
  TANKER_ERROR_RESOURCE_KEY_NOT_FOUND,
  TANKER_ERROR_USER_NOT_FOUND,
  TANKER_ERROR_DECRYPT_FAILED,
  TANKER_ERROR_INVALID_UNLOCK_KEY,
  TANKER_ERROR_INTERNAL_ERROR,
  TANKER_ERROR_INVALID_UNLOCK_PASSWORD,
  TANKER_ERROR_INVALID_VERIFICATION_CODE,
  TANKER_ERROR_UNLOCK_KEY_ALREADY_EXISTS,
  TANKER_ERROR_MAX_VERIFICATION_ATTEMPTS_REACHED,
  TANKER_ERROR_INVALID_GROUP_SIZE,
  TANKER_ERROR_RECIPIENT_NOT_FOUND,
  TANKER_ERROR_GROUP_NOT_FOUND,
  TANKER_ERROR_DEVICE_NOT_FOUND,
  TANKER_ERROR_IDENTITY_ALREADY_REGISTERED,

  TANKER_ERROR_LAST,
};

typedef uint32_t tanker_error_code_t;

struct tanker_error
{
  tanker_error_code_t code;
  const char* message;
};

void* tanker_future_get_voidptr(tanker_future_t* future);

enum tanker_event
{
  TANKER_EVENT_SESSION_CLOSED,
  TANKER_EVENT_DEVICE_CREATED,
  TANKER_EVENT_DEVICE_REVOKED,

  TANKER_EVENT_LAST,

};

typedef struct tanker_t tanker_t;
typedef struct tanker_options tanker_options_t;
typedef struct tanker_authentication_methods tanker_authentication_methods_t;
typedef struct tanker_sign_in_options tanker_sign_in_options_t;
typedef struct tanker_encrypt_options tanker_encrypt_options_t;
typedef char b64char;
typedef void (*tanker_log_handler_t)(char const* category,
                                     char level,
                                     const char* message);

typedef struct tanker_connection_t tanker_connection_t;
typedef void (*tanker_event_callback_t)(void* arg, void* data);

struct tanker_options
{
  uint8_t version;
  b64char const* trustchain_id;
  char const* trustchain_url;
  char const* writable_path;
  char const* sdk_type;
  char const* sdk_version;
};

struct tanker_authentication_methods
{
  uint8_t version;
  char const* password;
  char const* email;
};

struct tanker_sign_in_options
{
  uint8_t version;
  char const* unlock_key;
  char const* verification_code;
  char const* password;
};

struct tanker_encrypt_options
{
  uint8_t version;
  b64char const* const* recipient_public_identities;
  uint32_t nb_recipient_public_identities;
  b64char const* const* recipient_gids;
  uint32_t nb_recipient_gids;
};

const char* tanker_version_string(void);

void tanker_set_log_handler(tanker_log_handler_t handler);

tanker_future_t* tanker_create(const tanker_options_t* options);

tanker_future_t* tanker_destroy(tanker_t* tanker);

tanker_future_t* tanker_event_connect(tanker_t* tanker,
                                      enum tanker_event event,
                                      tanker_event_callback_t cb,
                                      void* data);

tanker_future_t* tanker_event_disconnect(tanker_t* tanker,
                                         tanker_connection_t* connection);

tanker_future_t* tanker_sign_up(
    tanker_t* tanker,
    char const* identity,
    tanker_authentication_methods_t const* authentication_methods);

tanker_future_t* tanker_sign_in(
    tanker_t* tanker,
    char const* identity,
    tanker_sign_in_options_t const* sign_in_options);

tanker_future_t* tanker_sign_out(tanker_t* tanker);

bool tanker_is_open(tanker_t* tanker);

tanker_future_t* tanker_device_id(tanker_t* session);

tanker_future_t* tanker_register_unlock(tanker_t* session,
                                        char const* new_email,
                                        char const* new_password);

tanker_future_t* tanker_generate_and_register_unlock_key(tanker_t* session);

tanker_future_t* tanker_revoke_device(tanker_t* session,
                                      b64char const* device_id);

uint64_t tanker_encrypted_size(uint64_t clear_size);

tanker_expected_t* tanker_decrypted_size(uint8_t const* encrypted_data,
                               uint64_t encrypted_size);

tanker_expected_t* tanker_get_resource_id(const uint8_t* encrypted_data,
                                        uint64_t encrypted_size);

tanker_future_t* tanker_encrypt(tanker_t* tanker,
                                uint8_t* encrypted_data,
                                const uint8_t* data,
                                uint64_t data_size,
                                tanker_encrypt_options_t const* options);

tanker_future_t* tanker_decrypt(tanker_t* session,
                                uint8_t* decrypted_data,
                                const uint8_t* data,
                                uint64_t data_size);

tanker_future_t* tanker_share(tanker_t* session,
                              char const* const* recipient_public_identities,
                              uint64_t nb_recipient_public_identities,
                              char const* const* recipient_gids,
                              uint64_t nb_recipient_gids,
                              b64char const* const* resource_ids,
                              uint64_t nb_resource_ids);

void tanker_free_buffer(void* buffer);

tanker_future_t* tanker_admin_connect(char const* trustchain_url,
                                      char const* id_token);

tanker_future_t* tanker_admin_create_trustchain(tanker_admin_t* admin,
                                                char const* name);

tanker_future_t* tanker_admin_delete_trustchain(tanker_admin_t* admin,
                                                char const* trustchain_id);

void tanker_admin_trustchain_descriptor_free(tanker_trustchain_descriptor_t* trustchain);


tanker_future_t* tanker_create_group(tanker_t* session,
                                     char const* const* member_uids,
                                     uint64_t nb_members);

tanker_future_t* tanker_update_group_members(tanker_t* session,
                                             char const* group_id,
                                             char const* const* users_to_add,
                                             uint64_t nb_users_to_add);
