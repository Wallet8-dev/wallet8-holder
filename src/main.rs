// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Wallet8:Holder
// SPDX-License-Identifier: Apache-2.0

//! Wallet8 Holder - the wallet backend service.
//! See `DESIGN.md` (the credential vault, the device keys, the
//! presentation history).
//! Boot runs on the platform `sentin8-shell` crate: registration flag,
//! PQ provider, config, capped pool, state binding, OpenAPI merge,
//! middleware stack and the PQ-TLS listener are owned by the shell.
//! This binary supplies only its registration data, state and routes.

#[allow(dead_code)]
mod handlers;
#[allow(dead_code)]
mod openapi;
mod registration;
#[allow(dead_code)]
mod server;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("wallet8:holder", "WALLET8_HOLDER")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::HolderOpenApi::openapi()),
    )
    .await
}
