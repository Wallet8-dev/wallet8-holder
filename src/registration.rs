// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Wallet8:Holder
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Wallet8:Holder.
//! Output via `--print-registration` flag. See
//! `sentin8/design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, M2mGrant, PgRole, Registration, SqlMigration,
};

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "wallet8:holder:read,wallet8:holder:write",
    role: "wallet8_holder_service",
    bypass_rls: false,
    // Grants live in the wallet8 vertical database only (DBX §6.6
    // database-per-vertical, schema-per-service).
    database: "wallet8",
    cross_schema_grants: &[],
}];

/// M2M DCR scope grants: the holder service's own client (the bus
/// produce/consume + the vault's event emit).
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "wallet8:holder",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "wallet8:holder:admin",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "holder",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "wallet8:holder:admin",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "holder-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// The admin scopes (the vault + keys + history surfaces).
const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "wallet8:holder:admin",
        scope: "wallet8:holder:credentials:read",
    },
    AdminScope::Typed {
        role: "wallet8:holder:admin",
        scope: "wallet8:holder:credentials:write",
    },
    AdminScope::Typed {
        role: "wallet8:holder:admin",
        scope: "wallet8:holder:credentials:revoke",
    },
    AdminScope::Typed {
        role: "wallet8:holder:admin",
        scope: "wallet8:holder:keys:read",
    },
    AdminScope::Typed {
        role: "wallet8:holder:admin",
        scope: "wallet8:holder:keys:write",
    },
    AdminScope::Typed {
        role: "wallet8:holder:admin",
        scope: "wallet8:holder:history:read",
    },
];

/// The RFW admin pages (the vault browser, the device keys, the
/// presentation history). Icons are Material Icons code points.
const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "/vault",
        label: "Credential Vault",
        ui_endpoint: "/v1/admin/ui/vault",
        data_endpoint: "/v1/admin/credentials",
        icon: "0xe0da",
    },
    AdminUiPage {
        route: "/device-keys",
        label: "Device Keys",
        ui_endpoint: "/v1/admin/ui/device-keys",
        data_endpoint: "/v1/admin/device-keys",
        icon: "0xe23e",
    },
    AdminUiPage {
        route: "/presentations",
        label: "Presentation History",
        ui_endpoint: "/v1/admin/ui/presentations",
        data_endpoint: "/v1/admin/presentations",
        icon: "0xe8b6",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    #[cfg(not(test))]
    let dump: fn() -> serde_json::Value = crate::OPENAPI_DUMP;
    #[cfg(test)]
    let dump: fn() -> serde_json::Value = || serde_json::Value::Null;

    let reg = Registration {
        service_type: "wallet8:holder",
        subdomain: "wallet8-holder",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        policies: &[],
        relations: &[],
        event_triggers: &[],
        schedules: &[],
        admin_ui: Some(AdminUi {
            label: "Holder",
            icon: "0xe919",
            service_flag: "holder",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: dump,
    };
    sentin8::registration::print_registration(section, &reg, dump)
}
