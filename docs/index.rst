Python Tanker SDK
=================

.. toctree::
    :hidden:

    changelog


.. module:: tankersdk


API
----

Overview
--------

Most of the API is exposed through the :class:`Tanker` class and uses
``async`` methods.

Here's a typical usage:

.. code-block:: python

   import asyncio
   from tankersdk import Tanker


   async def main():
         tanker = Tanker(app_id, writable_path=...)
         await tanker.open(user_id, user_token)
         alice_id = ...
         encrypted = await tanker.encrypt(b'I love you')


   if __name__ == "__main__":
      loop = asyncio.get_event_loop()
      loop.run_until_complete(main())


Detailed documentation follows:

Instantiation
+++++++++++++

.. autoclass:: Tanker

Session management
++++++++++++++++++

.. autoclass:: Status
   :members:
   :undoc-members:
   :member-order: bysource

.. autoclass:: VerificationMethodType
   :members:
   :undoc-members:

.. autoclass:: VerificationMethod


.. class:: Tanker

   .. automethod:: start
   .. automethod:: stop
   .. autoattribute:: status
   .. automethod:: register_identity
   .. automethod:: verify_identity
   .. automethod:: set_verification_method
   .. automethod:: get_verification_methods
   .. automethod:: revoke_device


Encryption and sharing
++++++++++++++++++++++

.. class:: Tanker

   .. automethod:: encrypt
   .. automethod:: decrypt

   .. automethod:: share

      Useful if the list of people to share with is not known when encrypting
      the data ::

         clear_data = b'important message'
         encrypted = await tanker.encrypted_data(clear_data)
         resource_id = tanker.get_resource_id(encrypted_data)
         await tanker.share(
            encrypted,
            users=["alice_identity", "bob_identity"]
         )

   .. automethod:: get_resource_id

Using Streams
+++++++++++++

Streams are useful when you want to use asynchronous I/O.

Here's an example, where data goes from `source` to `destination` using asynchronous reads and writes::

    class AsyncStream:
        def __init__(self, source):
            ...
        async def read(self, size: int) -> bytes:
            ...

        async def write(self, buffer: bytes) -> None:
            ...


    # encryption
    clear_stream = AsyncStream(source)
    encrypted_stream = await tanker.encrypt_stream(clear_stream)

    # decryption
    output_stream = AsyncStream(destination)
    async with await tanker.decrypt_stream(encrypted_data) as f:
        clear_data = await f.read()
        await output_stream.write(clear_data)


They also come in handy if the encrypted_data is so large it would not fit in memory, in this case, you can read the data by chunks, like this::


    chunk_size = 1024 ** 2
    async with await tanker.decrypt_stream(encrypted_data) as f:
        while True:
            clear_chunk = await f.read(chunk_size)
            if not clear_chunk:
                break
            await output_source.write(clear_chunk)


.. note:: If you want to use stream to read and write files, consider using the `aiofiles <https://pypi.org/project/aiofiles/>`_ library


.. autoclass:: StreamWrapper

    .. automethod:: read


.. class:: Tanker

   .. automethod:: encrypt_stream
   .. automethod:: decrypt_stream

Group management
++++++++++++++++

.. class:: Tanker

   .. automethod:: create_group
   .. automethod:: update_group_members

      The only supported operation (yet) is to add members to the group: ::

         # Create a group with user 1 and 2
         my_group = await tanker.create_group([user1, user2])
         await tanker.update_group_members(
            my_group,
            add=[user3, user4]
         )

         # The group now contains users 1 to 4, and can be used
         # directly with `encrypt()`:
         await tanker.encrypt(
             clear_data,
             share_with_groups=[my_group]
         )

Pre-registration
++++++++++++++++

.. autoclass:: AttachResult


.. class:: Tanker

   .. automethod:: attach_provisional_identity
   .. automethod:: verify_provisional_identity
