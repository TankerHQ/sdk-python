Tanker bindings for Python3
============================


Run the tests
-------------


.. code-block:: console
   # to be ran everytime code in ../Native or build_tanker.py changes:
   $ TANKER_NATIVE_BUILD_PATH=../Native/build python setup.py clean develop

   $ pytest -s



Server
------

Implement the same server used in https://github.com/SuperTanker/hello, but it Python

To run:

.. code-block:: console

   $ FLASK_DEBUG=1 FLASK_APP=server.py flask run

Note the `tankersdk/usertoken` module that contains the logic to generate user tokens server-side
