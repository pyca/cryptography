# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Default crypto material manager class."""
import logging

import attr

from ..exceptions import MasterKeyProviderError, SerializationError
from ..internal.crypto.authentication import Signer, Verifier
from ..internal.crypto.elliptic_curve import generate_ecc_signing_key
from ..internal.defaults import ALGORITHM, ENCODED_SIGNER_KEY
from ..internal.str_ops import to_str
from ..internal.utils import prepare_data_keys
from ..key_providers.base import MasterKeyProvider
from . import DecryptionMaterials, EncryptionMaterials
from .base import CryptoMaterialsManager

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=False)
class DefaultCryptoMaterialsManager(CryptoMaterialsManager):
    """Default crypto material manager.

    .. versionadded:: 1.3.0

    :param master_key_provider: Master key provider to use
    :type master_key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """

    algorithm = ALGORITHM
    master_key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyProvider))

    def _generate_signing_key_and_update_encryption_context(self, algorithm, encryption_context):
        """Generates a signing key based on the provided algorithm.

        :param algorithm: Algorithm for which to generate signing key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context from request
        :returns: Signing key bytes
        :rtype: bytes or None
        """
        _LOGGER.debug("Generating signing key")
        if algorithm.signing_algorithm_info is None:
            return None

        signer = Signer(algorithm=algorithm, key=generate_ecc_signing_key(algorithm=algorithm))
        encryption_context[ENCODED_SIGNER_KEY] = to_str(signer.encoded_public_key())
        return signer.key_bytes()

    def get_encryption_materials(self, request):
        """Creates encryption materials using underlying master key provider.

        :param request: encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :raises MasterKeyProviderError: if no master keys are available from the underlying master key provider
        :raises MasterKeyProviderError: if the primary master key provided by the underlying master key provider
            is not included in the full set of master keys provided by that provider
        """
        algorithm = request.algorithm if request.algorithm is not None else self.algorithm
        encryption_context = request.encryption_context.copy()

        signing_key = self._generate_signing_key_and_update_encryption_context(algorithm, encryption_context)

        primary_master_key, master_keys = self.master_key_provider.master_keys_for_encryption(
            encryption_context=encryption_context,
            plaintext_rostream=request.plaintext_rostream,
            plaintext_length=request.plaintext_length,
        )
        if not master_keys:
            raise MasterKeyProviderError("No Master Keys available from Master Key Provider")
        if primary_master_key not in master_keys:
            raise MasterKeyProviderError("Primary Master Key not in provided Master Keys")

        data_encryption_key, encrypted_data_keys = prepare_data_keys(
            primary_master_key=primary_master_key,
            master_keys=master_keys,
            algorithm=algorithm,
            encryption_context=encryption_context,
        )

        _LOGGER.debug("Post-encrypt encryption context: %s", encryption_context)

        return EncryptionMaterials(
            algorithm=algorithm,
            data_encryption_key=data_encryption_key,
            encrypted_data_keys=encrypted_data_keys,
            encryption_context=encryption_context,
            signing_key=signing_key,
        )

    def _load_verification_key_from_encryption_context(self, algorithm, encryption_context):
        """Loads the verification key from the encryption context if used by algorithm suite.

        :param algorithm: Algorithm for which to generate signing key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context from request
        :returns: Raw verification key
        :rtype: bytes
        :raises SerializationError: if algorithm suite requires message signing and no verification key is found
        """
        encoded_verification_key = encryption_context.get(ENCODED_SIGNER_KEY, None)

        if algorithm.signing_algorithm_info is not None and encoded_verification_key is None:
            raise SerializationError("No signature verification key found in header for signed algorithm.")

        if algorithm.signing_algorithm_info is None:
            if encoded_verification_key is not None:
                raise SerializationError("Signature verification key found in header for non-signed algorithm.")
            return None

        verifier = Verifier.from_encoded_point(algorithm=algorithm, encoded_point=encoded_verification_key)
        return verifier.key_bytes()

    def decrypt_materials(self, request):
        """Obtains a plaintext data key from one or more encrypted data keys
        using underlying master key provider.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        data_key = self.master_key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=request.encrypted_data_keys,
            algorithm=request.algorithm,
            encryption_context=request.encryption_context,
        )
        verification_key = self._load_verification_key_from_encryption_context(
            algorithm=request.algorithm, encryption_context=request.encryption_context
        )

        return DecryptionMaterials(data_key=data_key, verification_key=verification_key)
