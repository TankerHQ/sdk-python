// ctanker/async.h

typedef struct tanker_future tanker_future_t;
typedef struct tanker_future tanker_expected_t;
typedef struct tanker_promise tanker_promise_t;
typedef struct tanker_error tanker_error_t;

typedef void* (*tanker_future_then_t)(tanker_future_t* fut, void* arg);
/*!
 * Create a new empty promise.
 * \remark must call tanker_promise_destroy() to get rid of it.
 */
tanker_promise_t* tanker_promise_create(void);

/*!
 * Destroy a promise.
 * \pre promise must be allocated with tanker_promise_create().
 */
void tanker_promise_destroy(tanker_promise_t* promise);

/*!
 * Get a future from a promise.
 * \pre promise parameter must be allocated with tanker_promise_create().
 * \remark must call tanker_future_destroy"()" to get rid of the returned
 *         future.
 */
tanker_future_t* tanker_promise_get_future(tanker_promise_t* promise);

/*!
 * Set a promise value.
 * \pre promise parameter must be allocated with tanker_promise_create().
 */
void tanker_promise_set_value(tanker_promise_t* promise, void* value);


/*!
 * Get the content of the future.
 * \return The void pointer representing the value. Refer to the documentation
 * of the function returning the future to know how to interpret the value.
 */
void* tanker_future_get_voidptr(tanker_future_t* future);

/*!
 * Returns 1 if the future is ready, 0 otherwise.
 */
bool tanker_future_is_ready(tanker_future_t* future);

/*!
 * Block until the future is ready.
 * \pre future parameter must be allocated with tanker API.
 */
void tanker_future_wait(tanker_future_t* future);

/*!
 * Set a callback to the future chain.
 * \remark For the moment adding multiple callbacks is undefined
 * \param arg arguments for the callback.
 * \return A new future with the callback.
 * \remark The future returned has to be freed with tanker_future_destroy().
 */
tanker_future_t* tanker_future_then(tanker_future_t* future,
                                    tanker_future_then_t cb,
                                    void* arg);

/*!
 * Get the future error if any.
 *
 * \return The error contained in the future or NULL if there was no error.
 */
tanker_error_t* tanker_future_get_error(tanker_future_t* future);

/*!
 * Check if there is an error in the future.
 *
 * \return 0 if the future has no error, any other value otherwise.
 */
unsigned char tanker_future_has_error(tanker_future_t* future);

void tanker_future_destroy(tanker_future_t* future);


// ctanker/base64.h

typedef char b64char;

/*!
 * Get the size of a base64 encoded buffer given a buffer of \p decoded_size.
 */
uint64_t tanker_base64_encoded_size(uint64_t decoded_size);

/*!
 * Get the maximum decoded size possible from the size of the encoded data.
 */
uint64_t tanker_base64_decoded_max_size(uint64_t encoded_size);

/*!
 * Encode in base64 the buffer
 * \param to buffer to fill with the encoded data.
 * \pre to buffer must have been allocated with at least the size returned by
 *      the tanker_base64_encoded_size() function.
 * \param from buffer to encode
 * \pre from_size must be the size of the from parameter
 */
void tanker_base64_encode(b64char* to, void const* from, uint64_t from_size);

/*!
 * Decode the buffer with a base64
 * \param to buffer to fill with the decoded datas.
 * \pre to buffer must have been allocated with the size returned by the
 *      tanker_base64_decoded_size() function.
 * \param from buffer to decode
 * \pre from_size must be the size of the from parameter
 * \return an empty expected.
 */
tanker_expected_t* tanker_base64_decode(void* to,
                                        uint64_t* to_size,
                                        b64char const* from,
                                        uint64_t from_size);



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

// ctanker/ctanker.h

enum tanker_status
{
  TANKER_STATUS_STOPPED,
  TANKER_STATUS_READY,
  TANKER_STATUS_IDENTITY_REGISTRATION_NEEDED,
  TANKER_STATUS_IDENTITY_VERIFICATION_NEEDED,

  TANKER_STATUS_LAST
};

enum tanker_event
{
  TANKER_EVENT_SESSION_CLOSED,
  TANKER_EVENT_DEVICE_REVOKED,

  TANKER_EVENT_LAST,
};

enum tanker_verification_method_type
{
  TANKER_VERIFICATION_METHOD_EMAIL = 0x1,
  TANKER_VERIFICATION_METHOD_PASSPHRASE,
  TANKER_VERIFICATION_METHOD_VERIFICATION_KEY,

  TANKER_VERIFICATION_METHOD_LAST = TANKER_VERIFICATION_METHOD_VERIFICATION_KEY
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
typedef struct tanker_verification tanker_verification_t;
typedef struct tanker_verification_method tanker_verification_method_t;
typedef struct tanker_encrypt_options tanker_encrypt_options_t;
typedef struct tanker_log_record tanker_log_record_t;
typedef struct tanker_device_list_elem tanker_device_list_elem_t;
typedef struct tanker_device_list tanker_device_list_t;
typedef struct tanker_verification_method_list
    tanker_verification_method_list_t;
typedef struct tanker_attach_result tanker_attach_result_t;

/*!
 * \brief The list of a user's devices
 */
struct tanker_device_list
{
  tanker_device_list_elem_t* devices;
  uint32_t count;
};

/*!
 * \brief Describes one device belonging to the user
 */
struct tanker_device_list_elem
{
  b64char const* device_id;
  bool is_revoked;
};

/*!
 * \brief The list of a user verification methods
 */
struct tanker_verification_method_list
{
  tanker_verification_method_t* methods;
  uint32_t count;
};

/*!
 * \brief a struct describing a log message
 */
struct tanker_log_record
{
  char const* category;
  uint32_t level;
  char const* file;
  uint32_t line;
  char const* message;
};

/*!
 * \brief Callback type to filter Tanker SDK logs.
 * \discussion Should be used with tanker_set_log_handler.
 *
 * \param record a struct containing all message informations
 */
typedef void (*tanker_log_handler_t)(tanker_log_record_t const* record);

typedef struct tanker_connection tanker_connection_t;
typedef void (*tanker_event_callback_t)(void* arg, void* data);

/*!
 * Options used to create a tanker instance.
 */
struct tanker_options
{
  uint8_t version;
  b64char const* app_id; /*!< Must not be NULL. */
  char const* url;   /*!< Must not be NULL. */
  char const* writable_path;    /*!< Must not be NULL. */
  char const* sdk_type;         /*!< Must not be NULL. */
  char const* sdk_version;      /*!< Must not be NULL. */
};

struct tanker_email_verification
{
  uint8_t version;
  char const* email;
  char const* verification_code;
};

struct tanker_verification
{
  uint8_t version;
  // enum cannot be binded to java as they do not have a fixed size.
  // It takes a value from tanker_verification_method_type:
  uint8_t verification_method_type;
  union
  {
    char const* verification_key;
    tanker_email_verification_t email_verification;
    char const* passphrase;
  };
};

struct tanker_verification_method
{
  uint8_t version;
  // enum cannot be binded to java as they do not have a fixed size.
  // It takes a value from tanker_verification_method_type:
  uint8_t verification_method_type;
  union
  {
    char const* email;
  };
};

struct tanker_encrypt_options
{
  uint8_t version;
  b64char const* const* recipient_public_identities;
  uint32_t nb_recipient_public_identities;
  b64char const* const* recipient_gids;
  uint32_t nb_recipient_gids;
};

/*!
 * \brief a struct containing the result of an attach_provisional_identity()
 * If the status is TANKER_STATUS_READY, the method will be default initialized
 * with the values in TANKER_VERIFICATION_METHOD_INIT
 */
struct tanker_attach_result
{
  uint8_t version;
  // enum cannot be binded to java as they do not have a fixed size.
  // It takes a value from the enum tanker_status:
  uint8_t status;
  tanker_verification_method_t* method;
};

/*!
 * Allow to access version.
 * \return The current version of Tanker as a string.
 */
char const* tanker_version_string(void);

/*!
 * Set the log handler of the API with a function pointer
 * \param handler the function pointer, it must have the prototype of
 *        tanker_log_handler_t.
 */
void tanker_set_log_handler(tanker_log_handler_t handler);

/*!
 * Initialize the SDK
 */
void tanker_init(void);

/*!
 * Create a Tanker instance.
 * \param options struct tanker_options_t with the following preconditions.
 * \pre The *option* structure must not be NULL, as well as the fields
 *      specified in its documentation.
 * \return A tanker_future of a tanker_t*
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p options is NULL, or lacks mandatory
 *         fields, or has malformed fields
 */
tanker_future_t* tanker_create(tanker_options_t const* options);

/*!
 * Destroy a tanker instance.
 * \param tanker a tanker tanker_t* to be deleted.
 * \pre The tanker parameter has been allocated.
 * \return an async future.
 */
tanker_future_t* tanker_destroy(tanker_t* tanker);

/*!
 * Connect to an event.
 * \param tanker A tanker tanker_t* instance.
 * \param event The event to connect.
 * \param data The data to pass to the callback.
 * \return an expected of a tanker_connection_t* that must be disconnected with
 * tanker_event_disconnect().
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p event does not exist
 */
tanker_expected_t* tanker_event_connect(tanker_t* tanker,
                                        enum tanker_event event,
                                        tanker_event_callback_t cb,
                                        void* data);

/*!
 * Disconnect from an event.
 * \param tanker is not yet used.
 * \param event The event to disconnect.
 * \return an expected of NULL.
 */
tanker_expected_t* tanker_event_disconnect(tanker_t* tanker,
                                           enum tanker_event event);

/*!
 * Sign up to Tanker.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param identity the user identity.
 * \return a future of NULL
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p indentity is NULL
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
tanker_future_t* tanker_start(tanker_t* tanker, char const* identity);

/*!
 * Register a verification method associated with an identity.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param verification the verification methods to set up for the
 * user, or NULL.
 * \return a future of NULL
 * \throws TANKER_ERROR_INVALID_VERIFICATION_KEY unlock key is incorrect
 * \throws TANKER_ERROR_INVALID_VERIFICATION_CODE verification code is incorrect
 * \throws TANKER_ERROR_INVALID_UNLOCK_PASSWORD passphrase is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
tanker_future_t* tanker_register_identity(
    tanker_t* tanker, tanker_verification_t const* verification);

/*!
 * Verify an identity with provided verification.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param verification the verification methods to set up for the
 * user, or NULL.
 * \return a future of NULL
 * \throws TANKER_ERROR_INVALID_VERIFICATION_KEY unlock key is incorrect
 * \throws TANKER_ERROR_INVALID_VERIFICATION_CODE verification code is incorrect
 * \throws TANKER_ERROR_INVALID_UNLOCK_PASSWORD passphrase is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
tanker_future_t* tanker_verify_identity(
    tanker_t* tanker, tanker_verification_t const* verification);

/*!
 * Close a tanker session.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \pre tanker must be opened with tanker_open().
 */
tanker_future_t* tanker_stop(tanker_t* tanker);

/*!
 * The current Tanker status.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \return the current Tanker status.
 */
enum tanker_status tanker_status(tanker_t* tanker);

/*!
 * Get the current device id.
 * \param session A tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of b64char* that must be freed with tanker_free_buffer.
 */
tanker_future_t* tanker_device_id(tanker_t* session);

/*!
 * Get the list of the user's devices.
 * \param session A tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of tanker_device_list_t* that must be freed with
 * tanker_free_device_list.
 */
tanker_future_t* tanker_get_device_list(tanker_t* session);

/*!
 * Generate an verificationKey that can be used to accept a device
 * \param session A tanker tanker_t* instance
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of b64char* that must be freed with tanker_free_buffer
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
tanker_future_t* tanker_generate_verification_key(tanker_t* session);

/*!
 * Registers, or updates, the user's unlock claims,
 * creates an unlock key if necessary
 * \param session a tanker tanker_t* instance
 * \param verification a instance of tanker_verification_t
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future to void
 */
tanker_future_t* tanker_set_verification_method(
    tanker_t* session, tanker_verification_t const* verification);

/*!
 * Return all registered verification methods for the current user.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a tanker_verification_method_list_t*
 */
tanker_future_t* tanker_get_verification_methods(tanker_t* session);

/*!
 * Get the encrypted size from the clear size.
 * Must be called before encrypt to allocate the encrypted buffer.
 */
uint64_t tanker_encrypted_size(uint64_t clear_size);

/*!
 * Get the decrypted size.
 *
 * Must be called before decrypt to allocate the decrypted buffer.
 *
 * \return The size the decrypted data would take, cast to a void*, or an
 * error if the data is corrupted.
 * \throws TANKER_ERROR_DECRYPT_FAILED the
 * buffer is corrupt or truncated
 */
tanker_expected_t* tanker_decrypted_size(uint8_t const* encrypted_data,
                                         uint64_t encrypted_size);

/*!
 * Get the resource id from an encrypted data.
 * \return an already ready future of a string.
 */
tanker_expected_t* tanker_get_resource_id(uint8_t const* encrypted_data,
                                          uint64_t encrypted_size);

/*!
 * Encrypt data.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param encrypted_data The container for the encrypted data.
 * \pre encrypted_data must be allocated with a call to
 *      tanker_encrypted_size() in order to get the size beforehand.
 * \param data The array of bytes to encrypt.
 * \pre data_size must be the size of the *data* parameter
 *
 * \return An empty future.
 * \throws TANKER_ERROR_USER_NOT_FOUND at least one user to share with was not
 * found
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
tanker_future_t* tanker_encrypt(tanker_t* tanker,
                                uint8_t* encrypted_data,
                                uint8_t const* data,
                                uint64_t data_size,
                                tanker_encrypt_options_t const* options);

/*!
 * Decrypt an encrypted data.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param decrypted_data Decrypted array of bytes.
 * \pre decrypted_data must be allocated with a call to
 *      tanker_decrypted_size() in order to get the size beforehand.
 * \param data Array of bytes to decrypt.
 * \param data_size Size of the \p data argument.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_DECRYPT_FAILED The buffer was corrupt or truncated
 * \throws TANKER_ERROR_RESOURCE_KEY_NOT_FOUND The key was not found
 */
tanker_future_t* tanker_decrypt(tanker_t* session,
                                uint8_t* decrypted_data,
                                uint8_t const* data,
                                uint64_t data_size);

/*!
 * Share a symetric key of an encrypted data with other users.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param recipient_public_identities Array containing the recipients' public
 * identities.
 * \param nb_recipient_public_identities The number of recipients in
 * recipient_public_identities.
 * \param recipient_gids Array of strings describing the recipient groups.
 * \param nb_recipient_gids The number of groups in recipient_gids.
 * \param resource_ids Array of string describing the resources.
 * \param nb_resource_ids The number of resources in resource_ids.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_RECIPIENT_NOT_FOUND One of the recipients was not found,
 * no action was done
 * \throws TANKER_ERROR_RESOURCE_KEY_NOT_FOUND One of the
 * resource keys was not found, no action was done
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
tanker_future_t* tanker_share(tanker_t* session,
                              char const* const* recipient_public_identities,
                              uint64_t nb_recipient_public_identities,
                              char const* const* recipient_gids,
                              uint64_t nb_recipient_gids,
                              b64char const* const* resource_ids,
                              uint64_t nb_resource_ids);

/*!
 * Attach a provisional identity to the current user
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param provisional_identity provisional identity you want to claim.
 *
 * \return A future of tanker_attach_result_t*.
 * \throws TANKER_ERROR_NOTHING_TO_CLAIM there is nothing to claim for this
 * identity
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or
 * the server returned an error
 */
tanker_future_t* tanker_attach_provisional_identity(
    tanker_t* session, char const* provisional_identity);

/*!
 * Verifies a provisional identity to the current user
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param verification the verification used to verify this provisional
 * identity.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_NOTHING_TO_CLAIM there is nothing to claim for this
 * identity
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or
 * the server returned an error
 */
tanker_future_t* tanker_verify_provisional_identity(
    tanker_t* ctanker, tanker_verification_t const* verification);

/*!
 * Revoke a device by device id.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param device_id the device identifier as returned by tanker_device_id().
 *
 * \return An empty future.
 * \throws TANKER_DEVICE_NOT_FOUND The device_id in parameter does not
 * corresponds to a valid device
 * \throws TANKER_INVALID_ARGUMENT The device_id in parameter correspond to
 * another user's device.
 */
tanker_future_t* tanker_revoke_device(tanker_t* session,
                                      b64char const* device_id);

void tanker_free_buffer(void const* buffer);

void tanker_free_device_list(tanker_device_list_t* list);

void tanker_free_verification_method_list(
    tanker_verification_method_list_t* list);

void tanker_free_attach_result(tanker_attach_result_t* result);
// ctanker/groups.h

/*!
 * Create a group containing the given users.
 * Share a symetric key of an encrypted data with other users.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param public_identities_to_add Array of the group members' public identities.
 * \param nb_public_identities_to_add The number of members in public_identities_to_add.
 *
 * \return A future of the group ID as a string.
 * \throws TANKER_ERROR_USER_NOT_FOUND One of the members was not found, no
 * action was done
 * \throws TANKER_ERROR_INVALID_GROUP_SIZE The group is either empty, or has too
 * many members
 */
tanker_future_t* tanker_create_group(
    tanker_t* session,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add);

/*!
 * Updates an existing group, referenced by its groupId,
 * adding the user identified by their user Ids to the group's members.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param group_id The group ID returned by tanker_create_group
 * \param public_identities_to_add Array of the new group members' public identities.
 * \param nb_public_identities_to_add The number of users in public_identities_to_add.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_USER_NOT_FOUND One of the users was not found, no
 * action was done
 * \throws TANKER_ERROR_INVALID_GROUP_SIZE Too many users were added to the
 * group.
 */
tanker_future_t* tanker_update_group_members(
    tanker_t* session,
    char const* group_id,
    char const* const* public_identities_to_add,
    uint64_t nb_public_identities_to_add);

// ctanker/stream.h

typedef struct tanker_stream tanker_stream_t;
typedef struct tanker_stream_read_operation tanker_stream_read_operation_t;

typedef void (*tanker_stream_input_source_t)(
    uint8_t* buffer,
    int64_t buffer_size,
    tanker_stream_read_operation_t* operation,
    void* additional_data);

tanker_future_t* tanker_stream_encrypt(
    tanker_t* tanker,
    tanker_stream_input_source_t cb,
    void* additional_data,
    tanker_encrypt_options_t const* options);

tanker_future_t* tanker_stream_decrypt(
    tanker_t* tanker, tanker_stream_input_source_t cb, void* additional_data);

void tanker_stream_read_operation_finish(
    tanker_stream_read_operation_t* op, int64_t nb_read);

tanker_future_t *tanker_stream_read(tanker_stream_t *stream, uint8_t *buffer,
                                    int64_t buffer_size);

tanker_expected_t* tanker_stream_get_resource_id(tanker_stream_t* stream);
tanker_future_t* tanker_stream_close(tanker_stream_t* stream);

// ctanker/admin.h

typedef struct tanker_app_descriptor
{
  char const* name;
  b64char const* id;
  b64char const* private_key;
  b64char const* public_key;
} tanker_app_descriptor_t;

typedef struct tanker_admin tanker_admin_t;

/*!
 * Authenticates to the Tanker admin server API
 *
 * \param url The URL of the tanker server to connect to
 * \param id_token The authentication token string for the admin API
 * \return The admin instance. Free with tanker_admin_destroy.
 */
tanker_future_t* tanker_admin_connect(char const* url,
                                      char const* id_token);

/*!
 * Creates a new app
 *
 * \return The app. Free with tanker_admin_app_descriptor_free
 */
tanker_future_t* tanker_admin_create_app(tanker_admin_t* admin,
                                         char const* name);

/*!
 * Deletes the app permanently
 *
 * \return A future that resolves when the app has been deleted
 */
tanker_future_t* tanker_admin_delete_app(tanker_admin_t* admin,
                                         char const* app_id);

/*!
 * Frees the app descriptor structure
 */
void tanker_admin_app_descriptor_free(
    tanker_app_descriptor_t* app);

/*!
 * Disconnects and destroys the admin instance.
 *
 * \return A future that resolves when the instance has been deleted.
 */
tanker_future_t* tanker_admin_destroy(tanker_admin_t* admin);

/*!
 * Gets verification code of a user from the server
 */
tanker_future_t* tanker_admin_get_verification_code(
    tanker_admin_t* admin, char const* app_id, char const* user_email);


// cffi specific
extern "Python" void log_handler(tanker_log_record_t*);
extern "Python" void revoke_callback(void* arg, void* data);
extern "Python" void
stream_input_source_callback(uint8_t *buffer, int64_t buffer_size,
                             tanker_stream_read_operation_t *operation,
                             void *additional_data);
