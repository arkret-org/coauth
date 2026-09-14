# Planning the installation

This part of the documentation goes through installing the service, the important parts of the configuration file, and how to run the service.

Before going through the installation, it is important to understand the main
Arkret components and how they interact with each other.
coauth is the owning Station's deployment-private Account Authority component: it owns authentication, OAuth/OIDC, account sessions,
and Arkret session grants.

Downstream Stations such as Soland trust coauth-issued tokens and
session grants instead of receiving direct account-provisioning calls from
coauth.

At time of writing, the authentication service is meant to be run on a
standalone domain name (e.g. `auth.example.com`), and Soland on another
(e.g. `soland.example.com`). The auth domain is user-facing as part of the
authentication flow.

An example setup could look like this:

  - The authentication service is deployed on `auth.example.com`
  - Soland is deployed on `soland.example.com`

With the installation planned, it is time to go through the installation and configuration process.
The first section focuses on [installing the service](./installation.md).
