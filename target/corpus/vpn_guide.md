# Acme Corp VPN Guide

Acme uses GlobalProtect for remote access. The client is preinstalled on all
company laptops.

## Connecting

Open GlobalProtect, enter the portal address vpn.acme.internal, and sign in
with your SSO credentials and MFA prompt. The VPN is required for access to
internal tools such as Workday admin, the build farm, and file shares.

## Troubleshooting

If the connection drops repeatedly, switch networks or restart the client. If
you see "portal unreachable", check that your laptop clock is correct, then
open an IT ticket.
