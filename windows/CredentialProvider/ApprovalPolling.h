#pragma once

#include "../SavedCredential/SavedCredentialIpc.h"

namespace unlock_windows::credential_provider {
inline constexpr DWORD approvalPollInterval(saved_credential::AuthenticationStage stage) noexcept {
    using saved_credential::AuthenticationStage;
    // Approval may arrive between the offer query and the status query. Keep
    // polling quickly until the offer has been claimed, including approved.
    return stage == AuthenticationStage::verifying || stage == AuthenticationStage::approved ? 100 : 500;
}
}
