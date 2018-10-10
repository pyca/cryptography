To add downstream tests to be run in CI:

1. Create a test handler for the downstream consumer that you want to test.

   * The test handler should be a single file in the ``.travis/downstream.d/`` directory.
   * The file name should be ``{downstream name}.sh`` where ``{downstream name}``
     is the name that you wish to use to identify the consumer.
   * The test handler should accept a single argument that can be either ``install`` or ``run``.
     These should be used to separate installation of the downstream consumer and
     any dependencies from the actual running of the tests.

2. Add an entry to the test matrix in ``.travis.yml`` that sets the ``DOWNSTREAM``
   environment variable to the downstream name that you selected.
