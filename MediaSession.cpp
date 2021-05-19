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

#include "MediaSession.h"

#include <assert.h>
#include <iostream>
#ifdef OPTEE_AES128
#include <aes_crypto.h>
#else
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/opensslv.h>
#endif
#include <pthread.h>
#include <sstream>
#include <string>
#include <string.h>
#include <core/core.h>

#ifdef OPTEE_AES128
#define AES_BLOCK_SIZE CTR_AES_BLOCK_SIZE
#endif

#define DESTINATION_URL_PLACEHOLDER "http://no-valid-license-server"
#define NYI_KEYSYSTEM "keysystem-placeholder"
#define K_DECRYPTION_KEY_SIZE 16

using namespace std;
using namespace WPEFramework;

MODULE_NAME_DECLARATION(BUILD_REFERENCE);

namespace CDMi {

uint32_t MediaKeySession::s_sessionCnt = 10;
#ifdef OPTEE_AES128
static uint16_t tee_session_init = 0;
#endif

const char* MediaKeySession::CreateSessionId() {
    stringstream strs;
    strs << s_sessionCnt;

    char *buffer = new char[strs.str().length()]();
    strcpy(buffer, strs.str().c_str());

    s_sessionCnt++;

    return const_cast<char*>(buffer);
}

MediaKeySession::MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData) {
    m_sessionId = MediaKeySession::CreateSessionId();
    cout << "creating mediakeysession with id: " << m_sessionId << endl;

    std::string initData(reinterpret_cast<const char*>(f_pbInitData), f_cbInitData);
    std::string clearKeyInitData;

    if (!ParseClearKeyInitializationData(initData, &clearKeyInitData))
        clearKeyInitData = initData;
#ifdef OPTEE_AES128
    else {
        if(!tee_session_init) {
            TEE_crypto_init();
            std::cout << "ClearKey CDMi: TEE initialized." << std::endl;
        }
        tee_session_init++;
     }
#endif
}

MediaKeySession::~MediaKeySession() {
#ifdef OPTEE_AES128
    tee_session_init--;
    if(tee_session_init == 0)
        TEE_crypto_close();
#endif
}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {
    int ret;
    pthread_t thread;

    cout << "#mediakeysession.Run" << endl;

    if (f_piMediaKeySessionCallback) {
        m_piCallback = const_cast<IMediaKeySessionCallback*>(f_piMediaKeySessionCallback);

        ret = pthread_create(&thread, nullptr, MediaKeySession::_CallRunThread, this);
        if (ret == 0)
            pthread_detach(thread);
        else {
            cout << "#mediakeysession.Run: err: could not create thread" << endl;
            return;
        }
    } else
        cout << "#mediakeysession.Run: err: MediaKeySessionCallback NULL?" << endl;
}

void* MediaKeySession::_CallRunThread(void *arg) {
    return ((MediaKeySession*)arg)->RunThread(1);
}

void* MediaKeySession::_CallRunThread2(void *arg) {
    return ((MediaKeySession*)arg)->RunThread(2);
}

void* MediaKeySession::RunThread(int f_i) {
    cout << "#mediakeysession._RunThread" << endl;
    if (f_i == 1) {
        std::string message = KeyIdsToJSON();
        m_piCallback->OnKeyMessage((const uint8_t*)message.c_str(), message.size(), const_cast<char*>(DESTINATION_URL_PLACEHOLDER));
    }
    return (nullptr);
}

CDMi_RESULT MediaKeySession::Load(void) {
    return CDMi_S_FALSE;
}

void MediaKeySession::Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse) {
    int ret;
    pthread_t thread;

    cout << "#mediakeysession.Run" << endl;
    std::string keyString(reinterpret_cast<const char*>(f_pbKeyMessageResponse), f_cbKeyMessageResponse);
    // Session type is set to "0". We keep the function signature to
    // match Chromium's ExtractKeysFromJWKSet(...) function
    media::ExtractKeysFromJWKSet(keyString, m_keys, 0);

    ret = pthread_create(&thread, NULL, MediaKeySession::_CallRunThread2, this);
    if (!ret) {
        pthread_detach(thread);
    } else {
        cout << "#mediakeysession.Run: err: could not create thread" << endl;
        return;
    }
    if (m_piCallback) {
        for (auto& keyIdWithKey : m_keys)
            m_piCallback->OnKeyStatusUpdate("KeyUsable", reinterpret_cast<const uint8_t*>(keyIdWithKey.first.c_str()), keyIdWithKey.first.size());
        m_piCallback->OnKeyStatusesUpdated();
    }
}

CDMi_RESULT MediaKeySession::Remove(void) {
    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Close(void) {
    return CDMi_SUCCESS;
}

const char* MediaKeySession::GetSessionId(void) const {
    cout <<"Inside GetSessionId"<< endl;
    return m_sessionId;
}

const char* MediaKeySession::GetKeySystem(void) const {
    // FIXME:(fhg):
    return NYI_KEYSYSTEM;
}

CDMi_RESULT MediaKeySession::Decrypt(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t *f_pdwSubSampleMapping,
    uint32_t f_cdwSubSampleMapping,
    const uint8_t *f_pbIV,
    uint32_t f_cbIV,
    const uint8_t *f_pbData,
    uint32_t f_cbData,
    uint32_t *f_pcbOpaqueClearContent,
    uint8_t **f_ppbOpaqueClearContent,
    const uint8_t keyIdLength,
    const uint8_t* keyId,
    bool initWithLast15) {
    std::string kid((const char*)keyId, keyIdLength);
    uint8_t *out; /* Faked secure buffer */
    const char *key;

    uint8_t ivec[AES_BLOCK_SIZE] = { 0 };
    uint8_t ecount_buf[AES_BLOCK_SIZE] = { 0 };
    unsigned int block_offset = 0;


    assert(f_cbIV <= AES_BLOCK_SIZE);

    if (!f_pcbOpaqueClearContent) {
        cout << "ERROR: f_pcbOpaqueClearContent is NULL" << endl;
        return CDMi_S_FALSE;
    }

    if (m_keys.size() != 1)
        cout << "FIXME: We support only one key at the moment. Number keys: " << m_keys.size()<< endl;

    if (m_keys[kid].size() != K_DECRYPTION_KEY_SIZE) {
        cout << "ERROR: Wrong key size" << endl;
        return CDMi_S_FALSE;
    }

    /* complete all validation and create memory for out data */
    out = (uint8_t*) malloc(f_cbData * sizeof(uint8_t));

    key = m_keys[kid].c_str();

    memcpy(&(ivec[0]), f_pbIV, f_cbIV);

#ifdef OPTEE_AES128
    int result = TEE_AES_ctr128_encrypt(f_pbData, out, f_cbData, key, ivec, ecount_buf, &block_offset, 0, false/*secure on/off*/);
    if(result != CDMi_SUCCESS) {
        std::cout << "ClearKey CDMi: Failure: On Decryption. result = " << result << std::endl;
        goto fail;
    }
#else
    AES_KEY aesKey;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key), strlen(key) * 8, &aesKey);

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    CRYPTO_ctr128_encrypt(reinterpret_cast<const unsigned char*>(f_pbData), out, f_cbData, &aesKey, ivec, ecount_buf, &block_offset, (block128_f)AES_encrypt);
#else
    AES_ctr128_encrypt(reinterpret_cast<const unsigned char*>(f_pbData), out, f_cbData, &aesKey, ivec, ecount_buf, &block_offset);
#endif
#endif

    /* Return clear content */
    *f_pcbOpaqueClearContent = f_cbData;
    *f_ppbOpaqueClearContent = out;

    return CDMi_SUCCESS;
fail:
    free(out);
    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ){
    free(f_pbClearContentOpaque);
    return CDMi_SUCCESS;
}

std::string MediaKeySession::KeyIdsToJSON() {
    /* FIXME: This JSON consturctor is for proof of concept only.
     * We need to add a proper JSON library.
     */
    ostringstream result;
    std::string sep = "";

    result << "{\"" << media::kKeyIdsTag << "\" : [";
    for (auto& kid : m_kids) {
        result << sep << "\"" << media::Base64Encode(kid.c_str(), kid.size()) << "\"";
        sep = ",";
    }
    result << "],\"" << media::kTypeTag << "\":\"" << media::kTemporarySession << "\"}";
    return result.str();
}

bool MediaKeySession::ParseClearKeyInitializationData(const std::string& initData, std::string* output)
{
   bool result = false;
   const char identifier[] = { '"', 'k', 'i', 'd', 's', '"', ':', '\0' };

   /* keyids type */
   if(initData.find(identifier) != std::string::npos) {
       result = ParseKeyIdsInitData(initData, output) > 0 ? true : false;
   }
   else {
       result = ParseCENCInitData(initData, output) > 0 ? true : false;
   }
   return result;
}

using JSONStringArray = Core::JSON::ArrayType<Core::JSON::String>;

bool MediaKeySession::ParseKeyIdsInitData(const std::string& initData, std::string* output) {
    class InitData : public Core::JSON::Container {
    public:
        InitData() : Core::JSON::Container() , KeyIds() {
            Add(_T("kids"), &KeyIds);
        }
        virtual ~InitData() {
        }

    public:
        JSONStringArray KeyIds;
    } jsonData;

    output->clear();

    jsonData.FromString(initData);
    JSONStringArray::ConstIterator index(static_cast<const InitData&>(jsonData).KeyIds.Elements());

    TRACE_L1("Clearkey CDMi: initdata keyid(s):");
    while (index.Next() == true) {
        TRACE_L1("%s", index.Current().Value().c_str());
        std::string keyId = media::Base64Decode(index.Current().Value());
        m_kids.insert(keyId);
    }

    return m_kids.size() > 0 ? true : false;
}

bool MediaKeySession::ParseCENCInitData(const std::string& initData, std::string* output)
{
    BufferReader input(reinterpret_cast<const uint8_t*>(initData.data()), initData.length());

    static const uint8_t clearKeySystemId[] = {
        0x10, 0x77, 0xef, 0xec, 0xc0, 0xb2, 0x4d, 0x02,
        0xac, 0xe3, 0x3c, 0x1e, 0x52, 0xe2, 0xfb, 0x4b,
    };

    // one PSSH box consists of:
    // 4 byte size of the atom, inclusive.  (0 means the rest of the buffer.)
    // 4 byte atom type, "pssh".
    // (optional, if size == 1) 8 byte size of the atom, inclusive.
    // 1 byte version, value 0 or 1.  (skip if larger.)
    // 3 byte flags, value 0.  (ignored.)
    // 16 byte system id.
    // (optional, if version == 1) 4 byte key ID count. (K)
    // (optional, if version == 1) K * 16 byte key ID.
    // 4 byte size of PSSH data, exclusive. (N)
    // N byte PSSH data.
    while (!input.IsEOF()) {
        size_t startPosition = input.pos();

        // The atom size, used for skipping.
        uint64_t atomSize;

        if (!input.Read4Into8(&atomSize))
            return false;

        std::vector<uint8_t> atomType;
        if (!input.ReadVec(&atomType, 4))
            return false;

        if (atomSize == 1) {
            if (!input.Read8(&atomSize))
                return false;
        } else if (atomSize == 0)
            atomSize = input.size() - startPosition;

        if (memcmp(&atomType[0], "pssh", 4)) {
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition)))
                return false;
            continue;
        }

        uint8_t version;
        if (!input.Read1(&version))
            return false;

        if (version > 1) {
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition)))
                return false;
            continue;
        }

        // flags
        if (!input.SkipBytes(3))
            return false;

        // system id
        std::vector<uint8_t> systemId;
        if (!input.ReadVec(&systemId, sizeof(clearKeySystemId)))
            return false;

        if (memcmp(&systemId[0], clearKeySystemId, sizeof(clearKeySystemId))) {
            // skip non-Playready PSSH boxes.
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition)))
                return false;
            continue;
        }

        if (version == 1) {
            // v1 has additional fields for key IDs.  We can skip them.
            uint32_t numKeyIds;
            if (!input.Read4(&numKeyIds))
                return false;

            for (uint32_t i = 0; i < numKeyIds; i++) {
                std::string keyId;
                if (!input.ReadString(&keyId, 16))
                    return false;

                m_kids.insert(keyId);
            }
        }

        // size of PSSH data
        uint32_t dataLength;
        if (!input.Read4(&dataLength))
            return false;

        output->clear();
        if (!input.ReadString(output, dataLength))
            return false;

        return true;
    }

    // we did not find a matching record
    return false;
}

}  // namespace CDMi
