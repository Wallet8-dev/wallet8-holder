// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! The utoipa OpenApi surface (the registration's openapi dump).

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Wallet8 Holder",
        description = "The wallet backend service: the encrypted credential vault, the device-key registration, the presentation history.",
        version = "1.0.0",
    ),
    paths(
        crate::handlers::list_credentials,
        crate::handlers::store_credential,
        crate::handlers::get_credential,
        crate::handlers::register_key,
        crate::handlers::list_presentations,
    ),
)]
pub struct HolderOpenApi;
