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

namespace Confluent.Kafka.Internal
{
    internal enum PrivateKeyAlgorithm
    {
        DSA = 0,
        RSA = 1
    }

    internal class PrivateKeyAlgorithmAndBytes
    {
        public PrivateKeyAlgorithm PrivateKeyAlgorithm
        {
            get { return _privateKeyAlgorithm; }
        }

        public string PrivateKeyAlgorithmInUse
        {
            get
            {
                return PrivateKeyAlgorithm == PrivateKeyAlgorithm.DSA ? ManualConfigSettings.DSAAlgorithmName : ManualConfigSettings.RSAAlgorithmName;
            }
        }

        public byte[] RawData
        {
            get { return _rawData; }
        }

        private readonly PrivateKeyAlgorithm _privateKeyAlgorithm;
        private readonly byte[] _rawData;

        public PrivateKeyAlgorithmAndBytes(
            PrivateKeyAlgorithm privateKeyAlgorithm,
            byte[] rawData)
        {
            _privateKeyAlgorithm = privateKeyAlgorithm;
            _rawData = rawData;
        }
    }
}