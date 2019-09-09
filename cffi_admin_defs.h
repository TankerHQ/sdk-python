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

// ctanker/admin.h

typedef struct tanker_future tanker_future_t;
typedef char b64char;

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
