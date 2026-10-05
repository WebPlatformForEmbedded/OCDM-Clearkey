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

namespace CDMi {

class ClearKey : public IMediaKeys, public IMediaSystemMetrics {
public:
    ClearKey(ClearKey&&) = delete;
    ClearKey(const ClearKey&) = delete;
    ClearKey& operator=(ClearKey&&) = delete;
    ClearKey& operator=(const ClearKey&) = delete;

    ClearKey() = default;
    ~ClearKey() override = default;

public:
    // IMediaKeys overrides
    // ------------------------------------------------------------------------------------------
    CDMi_RESULT CreateMediaKeySession(
        const std::string & keySystem,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData,
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData,
        IMediaKeySession **f_ppiMediaKeySession) override {
        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData);

        return CDMi_SUCCESS;
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) override {
        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(
        IMediaKeySession *f_piMediaKeySession) override {

        if(f_piMediaKeySession)
            delete f_piMediaKeySession;

        return CDMi_SUCCESS;
    }

    // IMediaSystemMetrics overrides
    // ------------------------------------------------------------------------------------------
    CDMi_RESULT Metrics (uint32_t& bufferLength, uint8_t buffer[]) const override {
        bufferLength = 1;
        buffer[0] = 1;
        return CDMi_SUCCESS;
    }
};

static SystemFactoryType<ClearKey> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
