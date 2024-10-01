.. hazmat::

Nonces
======

.. module:: cryptography.hazmat.primitives.nonces

Nonces is a module to generate nonces for cryptographic purposes.  Algorithms like
:class:`cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20` and
modes like :class:`cryptography.hazmat.primitives.ciphers.modes.CTR` could leverage
these nonces.

When using nonces it is imperative NEVER to reuse ANY value returned by the class
along a single cryptographic key.


The module contains two main classes:
:class:`cryptography.hazmat.primitives.nonces.Nonce` and
:class:`cryptography.hazmat.primitives.nonces.Nonces`.


.. class:: Nonce(bytes)
   
   Each unique nonce value is an instantiated object of this bytes subclass.

   .. method:: from_bytes(nonce)
      
      Load a unique nonce value.

      :param nonce: nonce bytes.
      :return: Nonce object.

   .. method:: random(size)
      
      Get random Nonce from a size.

      :param size: size of the nonce.
      :return: Nonce object.

   Example of random nonce:

   .. doctest::

      from cryptography.hazmat.primitives.nonces import Nonce

      # This will generate a random one-time 24 bytes nonce
      nonce = Nonce.random(24)

.. class:: Nonces(size, counter_size, seed, order, trailing_counter)

   Nonces generator based on:
      - A given size.
      - A counter size.
      - An optional seed.
      - An optional byte order for the counter.
      - An optional trailing position argument for the counter.

   All nonces generated will use a counter.

   :param size: size of the full nonce (nonce + counter).
   :param counter_size: size of the counter.
   :param seed: seed to use for the non-counter portion of the nonce.
   :param order: byte order for the counter.
      "big" means big endian for the counter.
      "little" mean little endian for the counter.
   :param trailing_counter: trailing counter or not.
      True means nonce + counter
      False means counter + nonce

   Example of nonces with counter:

   .. doctest::

      from cryptography.hazmat.primitives.nonces import Nonces

      # This will initiate an 8 bytes nonce with a 4 bytes counter
      nonces = Nonces(size=8, counter_size=4)

      # By default the counter is big endian with a random seed
      # and the counter trailing at the end of the full nonce bytes

      # Get the current nonce
      nonce = nonces.nonce

      print(nonce)

   We can also use a specific seed:

   .. doctest::

      from cryptography.hazmat.primitives.nonces import Nonces

      # We can create a new object with the seed and change the byte order
      # to little endian and a non-trailing counter (i.e, counter + nonce)

      seed = b"\xff" * 4
      nonces = Nonces(
         size=8,
         counter_size=4,
         seed=seed,
         order='little',
         trailing_counter=False
      )
      for i in range(10):
         nonces.update()

      b'\x01\x00\x00\x00\xff\xff\xff\xff'
      b'\x02\x00\x00\x00\xff\xff\xff\xff'
      b'\x03\x00\x00\x00\xff\xff\xff\xff'
      b'\x04\x00\x00\x00\xff\xff\xff\xff'
      b'\x05\x00\x00\x00\xff\xff\xff\xff'
      b'\x06\x00\x00\x00\xff\xff\xff\xff'
      b'\x07\x00\x00\x00\xff\xff\xff\xff'
      b'\x08\x00\x00\x00\xff\xff\xff\xff'
      b'\t\x00\x00\x00\xff\xff\xff\xff'
      b'\n\x00\x00\x00\xff\xff\xff\xff'

      assert nonces.seed_bytes == seed

   .. method:: update()

      Update nonce value incrementing counter.

      :raises: OverflowError in case of counter overflow.
      :return: Current nonce.

   We can update to get the first counted nonce:

   .. doctest::
   
      # Update the current counter
      nonce = nonces.update()

      print(nonce)

   .. method:: set_counter(counter)

      Set counter to new value.

      :param counter: counter value.
      :raises: ValueError or AssertionError.
      :return: Current nonce.

   We can set the counter:

   .. doctest::

      nonce = nonces.set_counter(255)

      print(nonce)

      # Get the counter value
      print(nonces.counter)

      # Get the counter value in bytes
      nonces.counter_bytes

   If we try to set the counter to a lower value an exception will be triggered
   to avoid nonce reuse:

   .. doctest::

      try:
         nonce = nonces.set_counter(1)
      except Exception as e:
         print(e)

   If we run out of nonces an OverFlowError exception will be triggered:

   .. doctest::

      # nonces.max_counter is a property that returns the maximum counter available
      # for the counter bytes lenght

      nonces.set_counter(nonces.max_counter)
      try:
         nonces.update()
      except Exception as e:
         print(e)

   .. method:: counter_to_bytes()

      Get counter in bytes.

      :return: Counter bytes


   We can also set the increment value:

   .. doctest::

      from cryptography.hazmat.primitives.nonces import Nonces

      nonces = Nonces(size=8, counter_size=4, seed=seed)

      nonces.increment = 255

      for i in range(10):
         nonces.update()

      b'\xff\xff\xff\xff\x00\x00\x00\xff'
      b'\xff\xff\xff\xff\x00\x00\x01\xfe'
      b'\xff\xff\xff\xff\x00\x00\x02\xfd'
      b'\xff\xff\xff\xff\x00\x00\x03\xfc'
      b'\xff\xff\xff\xff\x00\x00\x04\xfb'
      b'\xff\xff\xff\xff\x00\x00\x05\xfa'
      b'\xff\xff\xff\xff\x00\x00\x06\xf9'
      b'\xff\xff\xff\xff\x00\x00\x07\xf8'
      b'\xff\xff\xff\xff\x00\x00\x08\xf7'
      b'\xff\xff\xff\xff\x00\x00\t\xf6'

   We can leverage bytes encoding options:

   .. doctest::

      from cryptography.hazmat.primitives.nonces import Nonce, Nonces

      nonces = Nonces(size=8, counter_size=4)

      nonce = nonces.nonce

      nonce_hex = nonce.hex()

      new_nonce = Nonce.fromhex(nonce_hex)

      assert nonce == new_nonce

   .. attribute:: counter_bytes

      :return: current nonce counter bytes.

   .. attribute:: seed_bytes

      :return: current nonce bytes without counter.

   .. attribute:: nonce

      :return: current nonce.

   .. attribute:: increment

      :return: current increment value.

   .. attribute:: order

      :return: current counter byte order.

   .. attribute:: counter

      :return: current counter value.

   .. attribute:: max_counter

      :return: max counter value.

   .. attribute:: size

      :return: full nonce size.

   .. attribute:: counter_size

      :return: counter size.

   .. attribute:: seed_size

      :return: nonce size without counter.
