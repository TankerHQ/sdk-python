Python Tanker SDK
=================

.. module:: tankersdk.core


API
----

Overview
--------

Most of the API is exposed through the :class:`Tanker` class and uses
``async`` methods.

Here's a typical usage:

.. code-block:: python

   import asyncio
   from tankersdk.core import Tanker


   async def main():
         tanker = Tanker(trustchain_id, writable_path=...)
         await tanker.open(user_id, user_token)
         alice_id = ...
         encrypted = await tanker.encrypt(b'I love you')


   if __name__ == "__main__":
      loop = asyncio.get_event_loop()
      loop.run_until_complete(main())


Detailed documentation follows:


Session management
++++++++++++++++++

.. autoclass:: Status
   :members:
   :undoc-members:
   :member-order: bysource

Instanciation
+++++++++++++

.. autoclass:: Tanker

   .. automethod:: open
   .. automethod:: close
   .. autoattribute:: status
   .. automethod:: register_unlock
   .. automethod:: unlock


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
            users=["alice_id", "bob_id"]
         )

   .. automethod:: get_resource_id


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
