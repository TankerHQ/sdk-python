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

extern "Python" void log_handler(const char* category, char level, const char* message);
extern "Python" void verification_callback(void* arg, void* data);

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
  TANKER_ERROR_UNUSED1,
  TANKER_ERROR_INVALID_ARGUMENT,
  TANKER_ERROR_RESOURCE_KEY_NOT_FOUND,
  TANKER_ERROR_USER_NOT_FOUND,
  TANKER_ERROR_DECRYPT_FAILED,
  TANKER_ERROR_INVALID_UNLOCK_EVENT_HANDLER,
  TANKER_ERROR_CHUNK_INDEX_OUT_OF_RANGE,
  TANKER_ERROR_VERSION_NOT_SUPPORTED,
  TANKER_ERROR_INVALID_UNLOCK_KEY,
  TANKER_ERROR_INTERNAL_ERROR,
  TANKER_ERROR_CHUNK_NOT_FOUND,
  TANKER_ERROR_INVALID_UNLOCK_PASSWORD,
  TANKER_ERROR_INVALID_VERIFICATION_CODE,
  TANKER_ERROR_UNLOCK_KEY_ALREADY_EXISTS,
  TANKER_ERROR_MAX_VERIFICATION_ATTEMPTS_REACHED,

  TANKER_ERROR_LAST,
};

typedef uint32_t tanker_error_code_t;

struct tanker_error
{
  tanker_error_code_t code;
  const char* message;
};

void* tanker_future_get_voidptr(tanker_future_t* future);

// tanker.h
enum tanker_status
{
  TANKER_STATUS_CLOSED,
  TANKER_STATUS_OPEN,
  TANKER_STATUS_USER_CREATION,
  TANKER_STATUS_DEVICE_CREATION,
  TANKER_STATUS_CLOSING,

  TANKER_STATUS_LAST
};

enum tanker_event
{
  TANKER_EVENT_UNUSED1,
  TANKER_EVENT_SESSION_CLOSED,
  TANKER_EVENT_DEVICE_CREATED,
  TANKER_EVENT_UNLOCK_REQUIRED,

  TANKER_EVENT_LAST
};

typedef struct tanker_t tanker_t;
typedef struct tanker_options tanker_options_t;
typedef struct tanker_encrypt_options tanker_encrypt_options_t;
typedef struct tanker_decrypt_options tanker_decrypt_options_t;
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
};


tanker_expected_t* tanker_generate_user_token(
    char const* trustchain_id,
    char const* trustchain_private_key,
    char const* user_id);


struct tanker_encrypt_options
{
  uint8_t version;
  const b64char* const* recipient_uids;
  uint64_t nb_recipients;
};

struct tanker_decrypt_options
{
  uint8_t version;
  uint64_t timeout;
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

tanker_future_t* tanker_open(tanker_t* tanker,
                             char const* user_id,
                             char const* user_token);

tanker_future_t* tanker_close(tanker_t* tanker);

enum tanker_status tanker_get_status(tanker_t* tanker);

tanker_future_t* tanker_setup_unlock(tanker_t* session,
                                     char const* email,
                                     char const* password);

tanker_future_t* tanker_unlock_current_device_with_password(tanker_t* session,
                                                            char const* pass);

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
                                uint64_t data_size,
                                tanker_decrypt_options_t const* options);

tanker_future_t* tanker_share(tanker_t* session,
                              const char* const* recipient_uids,
                              uint64_t nb_recipients,
                              const b64char* const* resource_ids,
                              uint64_t nb_resourceIds);

void tanker_free_buffer(void* buffer);

tanker_future_t* tanker_admin_connect(char const* trustchain_url,
                                      char const* id_token);

tanker_future_t* tanker_admin_create_trustchain(tanker_admin_t* admin,
                                                char const* name);

tanker_future_t* tanker_admin_delete_trustchain(tanker_admin_t* admin,
                                                char const* trustchain_id);

void tanker_admin_trustchain_descriptor_free(tanker_trustchain_descriptor_t* trustchain);
