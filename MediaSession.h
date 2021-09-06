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

class MediaKeySession : public IMediaKeySession {
public:
    MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData);
    virtual ~MediaKeySession();

// MediaKeySession overrides
    virtual void Run(
        const IMediaKeySessionCallback *f_piMediaKeySessionCallback);

    virtual CDMi_RESULT Load();

    virtual void Update(
        const uint8_t *f_pbKeyMessageResponse,
        uint32_t f_cbKeyMessageResponse);

    virtual CDMi_RESULT Remove();

    virtual CDMi_RESULT Close(void);

    virtual const char *GetSessionId(void) const;

    virtual const char *GetKeySystem(void) const;

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
        bool initWithLast15);

    virtual CDMi_RESULT ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque );

private:
    static void* _CallRunThread(
        void *arg);

    static void* _CallRunThread2(
        void *arg);

    void* RunThread(int f_i);
    static const char* CreateSessionId();
    bool ParseClearKeyInitializationData(const std::string& initData, std::string* output);

    bool ParseCENCInitData(const std::string& initData, std::string* output);
    bool ParseKeyIdsInitData(const std::string& initData, std::string* output);

    std::string KeyIdsToJSON();

private:
    const char *m_sessionId;
    static uint32_t s_sessionCnt;
    IMediaKeySessionCallback *m_piCallback;
    media::KeyIdAndKeyPairs m_keys;
    media::KeyIds m_kids;
};

}  // namespace CDMi
