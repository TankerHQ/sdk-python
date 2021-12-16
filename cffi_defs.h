// ctanker/async.h

typedef struct tanker_future tanker_future_t;
typedef struct tanker_future tanker_expected_t;
typedef struct tanker_promise tanker_promise_t;
typedef struct tanker_error tanker_error_t;

typedef void* (*tanker_future_then_t)(tanker_future_t* fut, void* arg);

tanker_promise_t* tanker_promise_create(void);

void tanker_promise_destroy(tanker_promise_t* promise);

tanker_future_t* tanker_promise_get_future(tanker_promise_t* promise);

void tanker_promise_set_value(tanker_promise_t* promise, void* value);

void* tanker_future_get_voidptr(tanker_future_t* future);

bool tanker_future_is_ready(tanker_future_t* future);

void tanker_future_wait(tanker_future_t* future);

tanker_future_t* tanker_future_then(tanker_future_t* future,
                                    tanker_future_then_t cb,
                                    void* arg);

tanker_error_t* tanker_future_get_error(tanker_future_t* future);

unsigned char tanker_future_has_error(tanker_future_t* future);

void tanker_future_destroy(tanker_future_t* future);

// ctanker/error.h

enum tanker_error_code
{
  TANKER_ERROR_INVALID_ARGUMENT = 1,
  TANKER_ERROR_INTERNAL_ERROR,
  TANKER_ERROR_NETWORK_ERROR,
  TANKER_ERROR_PRECONDITION_FAILED,
  TANKER_ERROR_OPERATION_CANCELED,

  TANKER_ERROR_DECRYPTION_FAILED,

  TANKER_ERROR_GROUP_TOO_BIG,

  TANKER_ERROR_INVALID_VERIFICATION,
  TANKER_ERROR_TOO_MANY_ATTEMPTS,
  TANKER_ERROR_EXPIRED_VERIFICATION,
  TANKER_ERROR_IO_ERROR,

  TANKER_ERROR_LAST,
};

typedef uint32_t tanker_error_code_t;

struct tanker_error
{
  tanker_error_code_t code;
  char const* message;
};

// ctanker/network.h

struct tanker_http_request
{
  char const* method;
  char const* url;
  char const* instance_id;
  char const* authorization;
  char const* body;
  int32_t body_size;
};

struct tanker_http_response
{
  char const* error_msg;
  char const* content_type;
  char const* body;
  int64_t body_size;
  int32_t status_code;
};

typedef struct tanker_http_request tanker_http_request_t;
typedef struct tanker_http_response tanker_http_response_t;

typedef void tanker_http_request_handle_t;

typedef tanker_http_request_handle_t* (*tanker_http_send_request_t)(
    tanker_http_request_t* request, void* data);
typedef void (*tanker_http_cancel_request_t)(
    tanker_http_request_t* request,
    tanker_http_request_handle_t* request_handle,
    void* data);

struct tanker_http_options
{
  tanker_http_send_request_t send_request;
  tanker_http_cancel_request_t cancel_request;
  void* data;
};

typedef struct tanker_http_options tanker_http_options_t;

void tanker_http_handle_response(tanker_http_request_t*,
                                 tanker_http_response_t*);

// ctanker/datastore.h

enum tanker_datastore_error_code
{
  TANKER_DATASTORE_ERROR_INVALID_DATABASE_VERSION = 1,
  TANKER_DATASTORE_ERROR_RECORD_NOT_FOUND,
  TANKER_DATASTORE_ERROR_DATABASE_ERROR,
  TANKER_DATASTORE_ERROR_DATABASE_LOCKED,
  TANKER_DATASTORE_ERROR_DATABASE_CORRUPT,
  TANKER_DATASTORE_ERROR_DATABASE_TOO_RECENT,
  TANKER_DATASTORE_ERROR_CONSTRAINT_FAILED,

  TANKER_DATASTORE_ERROR_LAST,
};

enum tanker_datastore_onconflict
{
  TANKER_DATASTORE_ONCONFLICT_FAIL,
  TANKER_DATASTORE_ONCONFLICT_IGNORE,
  TANKER_DATASTORE_ONCONFLICT_REPLACE,

  TANKER_DATASTORE_ONCONFLICT_LAST,
};

typedef void tanker_datastore_t;
typedef void tanker_datastore_error_handle_t;
typedef void tanker_datastore_device_get_result_handle_t;
typedef void tanker_datastore_cache_get_result_handle_t;

typedef void (*tanker_datastore_open_t)(tanker_datastore_error_handle_t* h,
                                        tanker_datastore_t** db,
                                        char const* data_path,
                                        char const* cache_path);
typedef void (*tanker_datastore_close_t)(tanker_datastore_t* db);

typedef void (*tanker_datastore_device_nuke_t)(
    tanker_datastore_t* datastore, tanker_datastore_error_handle_t* h);

typedef void (*tanker_datastore_put_serialized_device_t)(
    tanker_datastore_t* datastore,
    tanker_datastore_error_handle_t* h,
    uint8_t const* device,
    uint32_t device_size);
typedef void (*tanker_datastore_find_serialized_device_t)(
    tanker_datastore_t* datastore,
    tanker_datastore_device_get_result_handle_t* h);

typedef void (*tanker_datastore_put_cache_values_t)(
    tanker_datastore_t* datastore,
    tanker_datastore_error_handle_t* h,
    uint8_t const* const* keys,
    uint32_t const* key_sizes,
    uint8_t const* const* values,
    uint32_t const* value_sizes,
    uint32_t elem_count,
    uint8_t onconflict);
typedef void (*tanker_datastore_find_cache_values_t)(
    tanker_datastore_t* datastore,
    tanker_datastore_device_get_result_handle_t* h,
    uint8_t const* const* keys,
    uint32_t const* key_sizes,
    uint32_t elem_count);

struct tanker_datastore_options
{
  tanker_datastore_open_t open;
  tanker_datastore_close_t close;

  tanker_datastore_device_nuke_t nuke;
  tanker_datastore_put_serialized_device_t put_serialized_device;
  tanker_datastore_find_serialized_device_t find_serialized_device;
  tanker_datastore_put_cache_values_t put_cache_values;
  tanker_datastore_find_cache_values_t find_cache_values;
};

typedef struct tanker_datastore_options tanker_datastore_options_t;

uint8_t* tanker_datastore_allocate_device_buffer(
    tanker_datastore_device_get_result_handle_t* result_handle, uint32_t size);
void tanker_datastore_allocate_cache_buffer(
    tanker_datastore_cache_get_result_handle_t* result_handle,
    uint8_t** out_ptrs,
    uint32_t* sizes);
void tanker_datastore_report_error(tanker_datastore_error_handle_t* handle,
                                   uint8_t error_code,
                                   char const* message);

// ctanker/ctanker.h

enum tanker_status
{
  TANKER_STATUS_STOPPED,
  TANKER_STATUS_READY,
  TANKER_STATUS_IDENTITY_REGISTRATION_NEEDED,
  TANKER_STATUS_IDENTITY_VERIFICATION_NEEDED,

  TANKER_STATUS_LAST
};

enum tanker_verification_method_type
{
  TANKER_VERIFICATION_METHOD_EMAIL = 0x1,
  TANKER_VERIFICATION_METHOD_PASSPHRASE,
  TANKER_VERIFICATION_METHOD_VERIFICATION_KEY,
  TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN,
  TANKER_VERIFICATION_METHOD_PHONE_NUMBER,
  TANKER_VERIFICATION_METHOD_PREVERIFIED_EMAIL,
  TANKER_VERIFICATION_METHOD_PREVERIFIED_PHONE_NUMBER,
  TANKER_VERIFICATION_METHOD_E2E_PASSPHRASE,

  TANKER_VERIFICATION_METHOD_LAST
};

enum tanker_log_level
{
  TANKER_LOG_DEBUG = 1,
  TANKER_LOG_INFO,
  TANKER_LOG_WARNING,
  TANKER_LOG_ERROR,
};

typedef struct tanker tanker_t;
typedef struct tanker_options tanker_options_t;
typedef struct tanker_email_verification tanker_email_verification_t;
typedef struct tanker_phone_number_verification
    tanker_phone_number_verification_t;
typedef struct tanker_verification tanker_verification_t;
typedef struct tanker_verification_list tanker_verification_list_t;
typedef struct tanker_verification_method tanker_verification_method_t;
typedef struct tanker_verification_options tanker_verification_options_t;
typedef struct tanker_encrypt_options tanker_encrypt_options_t;
typedef struct tanker_sharing_options tanker_sharing_options_t;
typedef struct tanker_log_record tanker_log_record_t;
typedef struct tanker_device_list_elem tanker_device_list_elem_t;
typedef struct tanker_device_list tanker_device_list_t;
typedef struct tanker_verification_method_list
    tanker_verification_method_list_t;
typedef struct tanker_attach_result tanker_attach_result_t;

struct tanker_device_list
{
  tanker_device_list_elem_t* devices;
  uint32_t count;
};

struct tanker_device_list_elem
{
  char const* device_id;
  bool is_revoked;
};

struct tanker_verification_method_list
{
  tanker_verification_method_t* methods;
  uint32_t count;
};

struct tanker_verification_list
{
  uint8_t version;
  tanker_verification_t* verifications;
  uint32_t count;
};

struct tanker_log_record
{
  char const* category;
  uint32_t level;
  char const* file;
  uint32_t line;
  char const* message;
};

typedef void (*tanker_log_handler_t)(tanker_log_record_t const* record);

struct tanker_options
{
  uint8_t version;
  char const* app_id;          /*!< Must not be NULL. */
  char const* url;             /*!< Must not be NULL. */
  char const* persistent_path; /*!< Must not be NULL. */
  char const* cache_path;      /*!< Must not be NULL. */
  char const* sdk_type;        /*!< Must not be NULL. */
  char const* sdk_version;     /*!< Must not be NULL. */

  tanker_http_options_t http_options;
  tanker_datastore_options_t datastore_options;

  // We have a `version` field to handle ABI compatibility ourselves, tell cffi
  // to ignore extra fields.
  ...;
};

struct tanker_email_verification
{
  uint8_t version;
  char const* email;
  char const* verification_code;
};

struct tanker_phone_number_verification
{
  uint8_t version;
  char const* phone_number;
  char const* verification_code;
};

struct tanker_verification
{
  uint8_t version;
  // enum cannot be bound to java as they do not have a fixed size.
  // It takes a value from tanker_verification_method_type:
  uint8_t verification_method_type;
  char const* verification_key;
  tanker_email_verification_t email_verification;
  char const* passphrase;
  char const* e2e_passphrase;
  char const* oidc_id_token;
  tanker_phone_number_verification_t phone_number_verification;
  char const* preverified_email;
  char const* preverified_phone_number;
};

struct tanker_verification_method
{
  uint8_t version;
  // enum cannot be binded to java as they do not have a fixed size.
  // It takes a value from tanker_verification_method_type:
  uint8_t verification_method_type;
  char const* value;
};

struct tanker_verification_options
{
  uint8_t version;
  bool with_session_token;
  bool allow_e2e_method_switch;
};

struct tanker_encrypt_options
{
  uint8_t version;
  char const* const* share_with_users;
  uint32_t nb_users;
  char const* const* share_with_groups;
  uint32_t nb_groups;
  bool share_with_self;
  uint32_t padding_step;
};

struct tanker_sharing_options
{
  uint8_t version;
  char const* const* share_with_users;
  uint32_t nb_users;
  char const* const* share_with_groups;
  uint32_t nb_groups;
};

struct tanker_attach_result
{
  uint8_t version;
  // enum cannot be binded to java as they do not have a fixed size.
  // It takes a value from the enum tanker_status:
  uint8_t status;
  tanker_verification_method_t* method;
};

char const* tanker_version_string(void);

void tanker_set_log_handler(tanker_log_handler_t handler);

void tanker_init(void);

tanker_future_t* tanker_create(tanker_options_t const* options);

tanker_future_t* tanker_destroy(tanker_t* tanker);

tanker_future_t* tanker_start(tanker_t* tanker, char const* identity);

tanker_expected_t* tanker_enroll_user(tanker_t* tanker,
                                      char const* identity,
                                      tanker_verification_list_t const* verifications);

tanker_future_t* tanker_register_identity(
    tanker_t* tanker,
    tanker_verification_t const* verification,
    tanker_verification_options_t const* cverif_opts);

tanker_future_t* tanker_verify_identity(
    tanker_t* tanker,
    tanker_verification_t const* verification,
    tanker_verification_options_t const* cverif_opts);

tanker_future_t* tanker_stop(tanker_t* tanker);

tanker_future_t* tanker_create_oidc_nonce(tanker_t* tanker);

tanker_future_t* tanker_set_oidc_test_nonce(tanker_t* tanker, char const* nonce);

enum tanker_status tanker_status(tanker_t* tanker);

tanker_future_t* tanker_device_id(tanker_t* session);

tanker_future_t* tanker_get_device_list(tanker_t* session);

tanker_future_t* tanker_generate_verification_key(tanker_t* session);

tanker_future_t* tanker_set_verification_method(
    tanker_t* session,
    tanker_verification_t const* verification,
    tanker_verification_options_t const* cverif_opts);

tanker_future_t* tanker_get_verification_methods(tanker_t* session);

uint64_t tanker_encrypted_size(uint64_t clear_size, uint32_t padding_step);

tanker_expected_t* tanker_decrypted_size(uint8_t const* encrypted_data,
                                         uint64_t encrypted_size);

tanker_expected_t* tanker_get_resource_id(uint8_t const* encrypted_data,
                                          uint64_t encrypted_size);

tanker_future_t* tanker_encrypt(tanker_t* tanker,
                                uint8_t* encrypted_data,
                                uint8_t const* data,
                                uint64_t data_size,
                                tanker_encrypt_options_t const* options);

tanker_future_t* tanker_decrypt(tanker_t* session,
                                uint8_t* decrypted_data,
                                uint8_t const* data,
                                uint64_t data_size);

tanker_future_t* tanker_share(tanker_t* session,
                              char const* const* resource_ids,
                              uint64_t nb_resource_ids,
                              tanker_sharing_options_t* options);

tanker_future_t* tanker_attach_provisional_identity(
    tanker_t* session, char const* provisional_identity);

tanker_future_t* tanker_verify_provisional_identity(
    tanker_t* ctanker, tanker_verification_t const* verification);

void tanker_free_buffer(void const* buffer);

void tanker_free_device_list(tanker_device_list_t* list);

void tanker_free_verification_method_list(
    tanker_verification_method_list_t* list);

tanker_expected_t* tanker_prehash_password(char const* password);

void tanker_free_attach_result(tanker_attach_result_t* result);

// ctanker/groups.h

tanker_future_t* tanker_create_group(
    tanker_t* session,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add);

tanker_future_t* tanker_update_group_members(
    tanker_t* session,
    char const* group_id,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add,
    char const* const* public_identities_to_remove,
    uint64_t nb_public_identities_to_remove);

// ctanker/stream.h

typedef struct tanker_stream tanker_stream_t;
typedef struct tanker_stream_read_operation tanker_stream_read_operation_t;

typedef void (*tanker_stream_input_source_t)(
    uint8_t* buffer,
    int64_t buffer_size,
    tanker_stream_read_operation_t* operation,
    void* additional_data);

tanker_future_t* tanker_stream_encrypt(tanker_t* tanker,
                                       tanker_stream_input_source_t cb,
                                       void* additional_data,
                                       tanker_encrypt_options_t const* options);

tanker_future_t* tanker_stream_decrypt(tanker_t* tanker,
                                       tanker_stream_input_source_t cb,
                                       void* additional_data);

void tanker_stream_read_operation_finish(tanker_stream_read_operation_t* op,
                                         int64_t nb_read);

tanker_future_t* tanker_stream_read(tanker_stream_t* stream,
                                    uint8_t* buffer,
                                    int64_t buffer_size);

tanker_expected_t* tanker_stream_get_resource_id(tanker_stream_t* stream);
tanker_future_t* tanker_stream_close(tanker_stream_t* stream);

// ctanker/encryptionsession.h

typedef struct tanker_encryption_session tanker_encryption_session_t;

tanker_future_t* tanker_encryption_session_open(
    tanker_t* tanker, tanker_encrypt_options_t const* options);

tanker_future_t* tanker_encryption_session_close(
    tanker_encryption_session_t* session);

uint64_t tanker_encryption_session_encrypted_size(
    tanker_encryption_session_t* session, uint64_t clear_size);

tanker_expected_t* tanker_encryption_session_get_resource_id(
    tanker_encryption_session_t* session);

tanker_future_t* tanker_encryption_session_encrypt(
    tanker_encryption_session_t* session,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size);

tanker_future_t* tanker_encryption_session_stream_encrypt(
    tanker_encryption_session_t* session,
    tanker_stream_input_source_t cb,
    void* additional_data);

// cffi specific
extern "Python" void log_handler(tanker_log_record_t*);
extern "Python" void stream_input_source_callback(
    uint8_t* buffer,
    int64_t buffer_size,
    tanker_stream_read_operation_t* operation,
    void* additional_data);
