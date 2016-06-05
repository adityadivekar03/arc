=================================
[WIP] ARC Protocol Implementation
=================================

This project implements the module to process ARC headers in GNU Mailman.
------------------------------------------------------------------------

With the adoption of stricter email authentication policies to curb spam,
intermediate mail handlers like mailing lists suffer potential problems of
getting their mails flagged as spam and returning undelivered.

The solution for this lies in the recently drafted IETF ARC (Authenticated
Received Chain) protocol. From Mailman's point of view, ARC is a protocol that
can help mitigate denial of service to subscribed addresses at Yahoo!, AOL,
and other sites that have a `p = reject` DMARC policy and to the other service
providers that are set to migrate to the same policy soon. Setting up ARC would
allow Mailman to securely register its handling of the message, thus allowing
the set-up of a trust mechanism (not binding) between Mailman and the involved
MTAs and hence reducing the potential denial of service.

Modules
-------

* ARC Authentication Results 
* ARC Message Signature
* ARC Seal