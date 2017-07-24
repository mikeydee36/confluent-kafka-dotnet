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
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Confluent.Kafka.Internal
{
    internal class ManualConfigSettings
    {
        public const PrivateKeyAlgorithm DefaultPrivateKeyType = PrivateKeyAlgorithm.RSA;
        public const string DSAAlgorithmName = "DSA";
        public const string RSAAlgorithmName = "RSA";
        public const string SettingNameDefaultTopicConfig = "default.topic.config";
        public const string SettingNameSslCALocationInMemory = "ssl.ca.location_inmemory";
        public const string SettingNameSslCertificateLocationInMemory = "ssl.certificate.location_inmemory";
        public const string SettingNameSslKeyInMemory = "ssl.key_inmemory";
        public const string SettingNameSslKeyInMemoryType = "ssl.key_inmemory_type";

        public X509Certificate2 CAX509Certificate
        {
            get { return _caX509Certificate; }
        }

        public IEnumerable<KeyValuePair<string, object>> DefaultTopic
        {
            get { return _defaultTopic; }
        }

        public PrivateKeyAlgorithmAndBytes PrivateKeyAlgorithmAndBytes
        {
            get
            {
                byte[] privateKeyInBytes = PrivateKeyInBytes;
                if (privateKeyInBytes == null)
                    return null;

                return new PrivateKeyAlgorithmAndBytes(
                    PrivateKeyAlgorithm,
                    privateKeyInBytes);
            }
        }

        public byte[] PrivateKeyInBytes
        {
            get { return _privateKeyInBytes; }
        }

        public PrivateKeyAlgorithm PrivateKeyAlgorithm
        {
            get
            {
                return _privateKeyAlgorithm.HasValue ? _privateKeyAlgorithm.Value : DefaultPrivateKeyType;
            }
        }

        public IEnumerable<KeyValuePair<string, object>> UnprocessedConfigKeyValuePairs
        {
            get { return _unprocessedConfigKeyValuePairs; }
        }

        public X509Certificate2 X509Certificate
        {
            get { return _x509Certificate; }
        }

        private readonly IEnumerable<KeyValuePair<string, object>> _defaultTopic;
        private readonly IEnumerable<KeyValuePair<string, object>> _unprocessedConfigKeyValuePairs;
        private readonly PrivateKeyAlgorithm? _privateKeyAlgorithm;
        private readonly byte[] _privateKeyInBytes;
        private readonly X509Certificate2 _x509Certificate;
        private readonly X509Certificate2 _caX509Certificate;

        public ManualConfigSettings(
            X509Certificate2 caX509Certificate,
            IEnumerable<KeyValuePair<string, object>> defaultTopic,
            PrivateKeyAlgorithm? privateKeyAlgorithm,
            byte[] privateKeyInBytes,
            IEnumerable<KeyValuePair<string, object>> unprocessedConfigKeyValuePairs,
            X509Certificate2 x509Certificate)
        {
            _caX509Certificate = caX509Certificate;
            _defaultTopic = defaultTopic;
            _privateKeyAlgorithm = privateKeyAlgorithm;
            _privateKeyInBytes = privateKeyInBytes;
            _unprocessedConfigKeyValuePairs = unprocessedConfigKeyValuePairs;
            _x509Certificate = x509Certificate;
        }

        public static ManualConfigSettings Empty
        {
            get { return new ManualConfigSettings(); }
        }

        private ManualConfigSettings()
        {
        }

        public static ManualConfigSettings CreateFromConfigKeyValuePairs(IEnumerable<KeyValuePair<string, object>> config)
        {
            if (config == null)
                return Empty;

            X509Certificate2 caX509Certificate = null;
            IEnumerable<KeyValuePair<string, object>> defaultTopic = null;
            PrivateKeyAlgorithm? privateKeyAlgorithm = null;
            byte[] privateKeyInBytes = null;
            X509Certificate2 x509Certificate = null;

            var unprocessedKeyManualConfigSettings = new List<KeyValuePair<string, object>>();

            foreach (KeyValuePair<string, object> configSetting in config)
            {
                switch (configSetting.Key)
                {
                    case SettingNameDefaultTopicConfig:
                        defaultTopic = defaultTopic == null ? (IEnumerable<KeyValuePair<string, object>>)configSetting.Value : null;
                        break;
                    case SettingNameSslCALocationInMemory:
                        caX509Certificate = caX509Certificate == null ? (X509Certificate2)configSetting.Value : null;
                        break;
                    case SettingNameSslCertificateLocationInMemory:
                        x509Certificate = x509Certificate == null ? (X509Certificate2)configSetting.Value : null;
                        break;
                    case SettingNameSslKeyInMemory:
                        privateKeyInBytes = privateKeyInBytes == null ? (byte[])configSetting.Value : null;
                        break;
                    case SettingNameSslKeyInMemoryType:
                        if (!privateKeyAlgorithm.HasValue)
                        {
                            privateKeyAlgorithm = ((string)configSetting.Value).Equals(DSAAlgorithmName, StringComparison.OrdinalIgnoreCase)
                                ?
                                PrivateKeyAlgorithm.DSA
                                :
                                PrivateKeyAlgorithm.RSA;
                        }

                        unprocessedKeyManualConfigSettings.Add(configSetting);
                        break;
                    default:
                        unprocessedKeyManualConfigSettings.Add(configSetting);
                        break;
                }
            }

            return new ManualConfigSettings(
                caX509Certificate: caX509Certificate,
                defaultTopic: defaultTopic,
                privateKeyAlgorithm: privateKeyAlgorithm,
                privateKeyInBytes: privateKeyInBytes,
                unprocessedConfigKeyValuePairs: unprocessedKeyManualConfigSettings,
                x509Certificate: x509Certificate);
        }
    }
}