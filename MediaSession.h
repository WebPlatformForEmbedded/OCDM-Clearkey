/*
 * Copyright 2014 Fraunhofer FOKUS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#define MODULE_NAME OCDM_ClearKey

//#include "cdmi.h"
#include <interfaces/IDRM.h>
#include "JSONWebKey.h"
#include "KeyPairs.h"

namespace CDMi {

class MediaKeySession : public IMediaKeySession, public IMediaSessionMetrics {
public:
    MediaKeySession() = delete;
    MediaKeySession(MediaKeySession&&) = delete;
    MediaKeySession(const MediaKeySession&) = delete;
    MediaKeySession& operator= (MediaKeySession&&) = delete;
    MediaKeySession& operator= (const MediaKeySession&) = delete;

    MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData);
    ~MediaKeySession() override;

public:
    // IMediaKeySession overrides
    // ------------------------------------------------------------------------------------------
    const char* GetSessionId() const override;
    const char* GetKeySystem() const override;

    void Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) override;
    void Update(const uint8_t* f_pbKeyMessageResponse, uint32_t f_cbKeyMessageResponse) override;

    CDMi_RESULT Load() override;
    CDMi_RESULT Remove() override;
    CDMi_RESULT Close() override;
    CDMi_RESULT Decrypt( 
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const EncryptionScheme encryptionScheme,
        const EncryptionPattern& pattern,
        const uint8_t *f_pbIV,
        uint32_t f_cbIV,
        uint8_t *f_pbData,
        uint32_t f_cbData,
        uint32_t *f_pcbOpaqueClearContent,
        uint8_t **f_ppbOpaqueClearContent,
        const uint8_t keyIdLength,
        const uint8_t* keyId,
        bool initWithLast15) override;
    CDMi_RESULT ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque ) override;

    // IMediaSessionMetrics overrides
    // ------------------------------------------------------------------------------------------
    CDMi_RESULT Metrics (uint32_t& bufferLength, uint8_t buffer[]) const override;

private:
    static void* _CallRunThread(void *arg);
    static void* _CallRunThread2(void *arg);

    static const char* CreateSessionId();

    void* RunThread(int f_i);
    bool ParseClearKeyInitializationData(const std::string& initData, std::string* output);

    bool ParseCENCInitData(const std::string& initData, std::string* output);
    bool ParseKeyIdsInitData(const std::string& initData, std::string* output);

    std::string KeyIdsToJSON();

private:
    const char* m_sessionId;
    IMediaKeySessionCallback* m_piCallback;
    media::KeyIdAndKeyPairs m_keys;
    media::KeyIds m_kids;

    static uint32_t s_sessionCnt;
};

}  // namespace CDMi
