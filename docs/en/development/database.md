# Database

Interactions with the database go through `diesel` with `diesel-async` for async support and `deadpool` for connection pooling.

## Writing database interactions

All database interactions are done through repository traits. Each repository trait usually manages one type of data, defined in the [`coauth-data-model`][coauth-data-model] crate.

Defining a new data type and associated repository looks like this:

 - Define new structs in [`coauth-data-model`][coauth-data-model] crate
 - Define the repository trait in [`coauth-storage`][coauth-storage] crate
 - Make that repository trait available via the `RepositoryAccess` trait in [`coauth-storage`][coauth-storage] crate
 - Setup the database schema by writing a migration file in [`coauth-storage-postgres`][coauth-storage-postgres] crate
 - Implement the new repository trait in [`coauth-storage-postgres`][coauth-storage-postgres] crate
 - Write tests for the PostgreSQL implementation in [`coauth-storage-postgres`][coauth-storage-postgres] crate

Some of those steps are documented in more details in the [`coauth-storage`][coauth-storage] and [`coauth-storage-postgres`][coauth-storage-postgres] crates.

[coauth-data-model]: ../rustdoc/coauth_data_model/index.html
[coauth-storage]: ../rustdoc/coauth_storage/index.html
[coauth-storage-postgres]: ../rustdoc/coauth_storage_postgres/index.html

## Migrations

Migration files live in the `migrations` folder in the `coauth-storage-postgres` crate and are managed by `diesel_migrations`.

Note that migrations are embedded in the final binary and can be run from the service CLI tool.
