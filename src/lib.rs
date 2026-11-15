// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! Wallet8 Holder - library re-exports for integration tests.
//! The registration module is BINARY-only (it reads the crate-root
//! `OPENAPI_DUMP` static from `main.rs`).

pub mod handlers;
pub mod openapi;
pub mod server;
