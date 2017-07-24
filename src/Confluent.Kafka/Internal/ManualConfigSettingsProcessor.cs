// Copyright 2016-2017 Confluent Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Refer to LICENSE for more information.

using System;
#if !NET45
using System.Security.Cryptography;
#endif
using System.Security.Cryptography.X509Certificates;
using Confluent.Kafka.Impl;

namespace Confluent.Kafka.Internal
{
    internal static class ManualConfigSettingsProcessor
    {
        public static void ProcessConfigSettings(
            SafeConfigHandle configHandle,
            IntPtr configPtr,
            ManualConfigSettings ManualConfigSettings)
        {
            ProcessInMemoryCertificatesIfConfigured(
                configHandle, 
                configPtr, 
                ManualConfigSettings);
        }

        private static void ProcessInMemoryCertificatesIfConfigured(
            SafeConfigHandle configHandle,
            IntPtr configPtr,
            ManualConfigSettings ManualConfigSettings)
        {
            if (ManualConfigSettings.X509Certificate == null)
                return;

            X509Certificate2 caCertificate = ManualConfigSettings.CAX509Certificate;
            if (caCertificate == null)
                caCertificate = AttemptToResolveCACertificateFromUserCertificate(ManualConfigSettings.X509Certificate);

            if (caCertificate == null)
                throw new InvalidOperationException("An accompanying in-memory CA certificate must be provided");

            PrivateKeyAlgorithmAndBytes privateKeyAlgorithmAndBytes = ManualConfigSettings.PrivateKeyAlgorithmAndBytes;

            if (privateKeyAlgorithmAndBytes == null)
                privateKeyAlgorithmAndBytes = AttemptToResolvePrivateKeyFromUserCertificate(ManualConfigSettings.X509Certificate);

            if (privateKeyAlgorithmAndBytes == null)
                throw new InvalidOperationException("A private key must accompany the in-memory certificate");

            LibRdKafka.conf_set_bytes(
                configPtr, 
                ManualConfigSettings.SettingNameSslCertificateLocationInMemory, 
                ManualConfigSettings.X509Certificate.RawData);

            LibRdKafka.conf_set_bytes(
                configPtr, 
                ManualConfigSettings.SettingNameSslCALocationInMemory, 
                caCertificate.RawData);

            LibRdKafka.conf_set_bytes(
                configPtr, 
                ManualConfigSettings.SettingNameSslKeyInMemory, 
                privateKeyAlgorithmAndBytes.RawData);

            configHandle.Set(
                ManualConfigSettings.SettingNameSslKeyInMemoryType, 
                privateKeyAlgorithmAndBytes.PrivateKeyAlgorithmInUse);
        }

        private static X509Certificate2 AttemptToResolveCACertificateFromUserCertificate(X509Certificate2 userCertificate)
        {
#if NET45
            X509Chain certificateChain = X509Chain.Create();
#elif NETSTANDARD1_3
            using (var certificateChain = new X509Chain())
#else
            using (var certificateChain = new X509Chain(true))
#endif
            {
                certificateChain.Build(userCertificate);

                return certificateChain.ChainElements.Count > 1
                    ?
                    certificateChain.ChainElements[certificateChain.ChainElements.Count - 1].Certificate
                    :
                    null;
            }
        }

        private static PrivateKeyAlgorithmAndBytes AttemptToResolvePrivateKeyFromUserCertificate(X509Certificate2 userCertificate)
        {
            if (!userCertificate.HasPrivateKey)
                throw new InvalidOperationException("In-memory certificate must have a private key assigned to it");

#if (!NET45 && !NETSTANDARD1_3)
            const CngExportPolicies requiredPrivateKeyExportPolicies = CngExportPolicies.AllowPlaintextExport;
            CngKeyBlobFormat exportFormat = CngKeyBlobFormat.Pkcs8PrivateBlob;

#if (!NET46)
            DSACng dsaCng = userCertificate.GetDSAPrivateKey() as DSACng;
            if (dsaCng != null)
            {
                using (dsaCng)
                {
                    if (!dsaCng.Key.ExportPolicy.HasFlag(requiredPrivateKeyExportPolicies))
                        throw new InvalidOperationException("In-memory certificate must be marked as exportable when importing to be used");

                    return new PrivateKeyAlgorithmAndBytes(
                        PrivateKeyAlgorithm.DSA,
                        dsaCng.Key.Export(exportFormat));
                }
            }
#endif

            RSACng rsaCng = userCertificate.GetRSAPrivateKey() as RSACng;
            if (rsaCng != null)
            {
                using (rsaCng)
                {
                    if (!rsaCng.Key.ExportPolicy.HasFlag(requiredPrivateKeyExportPolicies))
                        throw new InvalidOperationException("In-memory certificate must be marked as exportable when importing to be used");

                    return new PrivateKeyAlgorithmAndBytes(
                        PrivateKeyAlgorithm.RSA,
                        rsaCng.Key.Export(exportFormat));
                }
            }
#endif

            throw new InvalidOperationException("In-memory certificate has an unknown type of private key and cannot be used");
        }
    }
}