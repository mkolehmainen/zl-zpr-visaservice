# API Summary

| METHOD | PATH | EXPLAIN |
| :---- | :---- | :---- |
| GET | `/admin/policies` | list policies |
| GET | `/admin/policies/{ID}` | get policy with ID |
| GET | `/admin/policy` | get the current policy for configuration |
| POST | `/admin/policy` | install a policy |
| GET | `/admin/visas` | list visas |
| GET | `/admin/visas/{ID}` | get visa with ID |
| DELETE | `/admin/visas/{ID}` | revoke a visa by its ID |
| GET | `/admin/actors` | list connected actors (ZPR address plus optional CN) |
| GET | `/admin/actors?role=node` | list connected nodes |
| GET | `/admin/actors/{zpr_addr}` | get the actor at the given ZPR address |
| DELETE | `/admin/actors/{zpr_addr}` | kick the live session of the actor at the given ZPR address |
| GET | `/admin/actors/{zpr_addr}/visas` | get visa ids related to the actor at the given ZPR address |
| GET | `/admin/services` | a service-oriented list of connected actors |
| GET | `/admin/services/{ID}` | gets service with ID |
| GET | `/admin/authrevoke` | returns list of revocation IDs |
| POST | `/admin/authrevoke` | add revocation to the table |
| POST | `/admin/authrevoke/clear` | clear the revocation table |
| GET | `/admin/authrevoke/{ID}` | get the specific information about this revocation |
| DELETE | `/admin/authrevoke/{ID}` | remove specific revocation |

NOTE: I would generalize the all the /admin/list/\_\_\_ functions into one value, but the return JSON is quite different for each thing that needs to be returned it doesn't quite make sense

## List policies `GET /admin/policies`

Returns:

```json
    {
        "config_ids": ["ID"],
    }
```

NOTE: Not sure it is correct that returning an individual policy and the current policy should be the same

## Get policy `GET /admin/policies/{ID}`

Returns:

```json
{
    "config_id": "ID",
    "version": "VERSION", 
    "format": "FORMAT",
    "container": "CONTAINER",
}

```

## 

## 

## Get current policy `GET /admin/policy`

Returns:

```json
{
    "config_id": "ID",
    "version": "VERSION",
    "format": "FORMAT",
    "container": "CONTAINTER",
}
```

## Install policy `POST /admin/policy`

Returns:

```json
{
    "config_id": "",
    "version": "",
    "format": "FORMAT",
    "container": "CONTAINTER",
}
```

## List visas `GET /admin/visas`

Returns:

```json
{
    "visa_ids": [ID],
}

```

## Get visa `GET /admin/visas/{ID}`

Returns:

```json
{
    "visa_id": ID,
    "expires": EXPIRES_MS,
    "created": CREATED,
    "actor_id": "ID",
    "policy_id": "ID",
    "source_addr": "SOURCE_ADDR",
    "dest_addr": "DEST_ADDR",
    "source_port": "SOURCE_PORT",
    "dest_port": "DEST_PORT",
    "proto": "PROTO",
}

```

## Revoke visa `DELETE /admin/visas/{ID}`

Returns:

```json
{
    "identifier": "IDEN",
    "revoked_visas": "ID"
}
```

## List actors `GET /admin/actors`

Actors are keyed by ZPR address. `cn` is a display label that may be null
(e.g. an OIDC-only connect).

Returns an array of ActorEntry:

```json
[
    { "zpr_addr": "ADDR", "cn": "CN" },
    { "zpr_addr": "ADDR", "cn": null }
]
```

## List nodes `GET /admin/actors?role=node`

Same shape, filtered to node actors (an invalid role value is a 400):

```json
[
    { "zpr_addr": "ADDR", "cn": "CN" }
]
```

## Get actor `GET /admin/actors/{zpr_addr}`

Used to get both actors and nodes, since nodes are a special type of actors.
The path segment is the actor's ZPR address; a malformed address is a 400,
an unknown one a 404.

Returns:

```json
{
    "cn": "CN or null",
    "created": CTIME_S,
    "ident": "IDENT",
    "node": NODE_BOOL,
    "zpr_addr": "ADDR",
    "attrs": [{ "key": "KEY", "value": ["VALUE"], "expires_at": EXP_S }],
    "auth_exp": EXP_S_OR_NULL,
    "node_details": {
        "connect_requests": REQS,
        "in_sync": SYNC_BOOL,
        "last_contact": CONTACT,
        "pending_install": PENDING,
        "visa_requests": REQS,
    },
}
```

`cn` is null for actors without a CN (e.g. an OIDC-only connect).
`node_details` is null for non-node actors (further fields elided above; see
`admin-http-api.txt` for the full NodeRecordBrief shape).

## Revoke actor `DELETE /admin/actors/{zpr_addr}`

Kicks the actor's live session; its credential is untouched (credential
revocation is `/admin/authrevoke`). Placeholder: the address is validated
(400 malformed, 404 unknown) but the response is fixed.

Returns:

```json
{
    "id": "IDEN",
    "revoked": [ID1, ID2]
}
```

## Visa IDs by actor `GET /admin/actors/{zpr_addr}/visas`

A malformed address is a 400, an unknown one a 404.

Returns:

```json
[
    { "id": ID }
]
```

## List services `GET /admin/services`

Returns:

```json
{
    "cn": ["CN"],
}
```

## Get service `GET /admin/services/{ID}`

Returns:

```json
{
    "id": "CN",
    "actor_id": CTIME_S,
}
```

## Get revoked list `GET /admin/authrevoke`

Returns:

```json
{
    "revokes": ["ID1", "ID2", "..."]
}
```

## Add revocation to list `POST /admin/authrevoke`

Not exactly sure what this has to take \- probably a FiveTuple or however we are going to identify a Visa

Different from DELETE /admin/visas/{ID} because it can be added to the revoke list before the visa is in the table

Returns:

```json
{
    "revoke": "ID"
}
```

## Clear revoked list `GET /admin/authrevoke/clear`

Returns:

```json
{
    "cleared_revokes": ["ID1", "ID2", "..."]
}

```

## Remove revocation `POST /admin/authrevoke`

Send a visa identifier

```json
{
    "visa_id": "",
    "expires": "",
    "created": "",
    "actor_id": "ID",
    "policy_id": "ID",
    "source_addr": "SOURCE_ADDR",
    "dest_addr": "DEST_ADDR",
    "source_port": "SOURCE_PORT",
    "dest_port": "DEST_PORT",
    "proto": "PROTO",
}
```

Different from DELETE /admin/visas/{ID} because it can be added to the revoke list before the visa is in the table

Returns:

```json
{
    "revoke": "ID"
}
```

## Get revocation `GET /admin/authrevoke/{ID}`

Returns:

```json
{
    "visa_id": ID,
    "expires": EXPIRES_MS,
    "created": CREATED,
    "actor_id": "ID",
    "policy_id": "ID",
    "source_addr": "SOURCE_ADDR",
    "dest_addr": "DEST_ADDR",
    "source_port": "SOURCE_PORT",
    "dest_port": "DEST_PORT",
    "proto": "PROTO",
}
```

## Remove revocation `DELETE /admin/authrevoke/{ID}`

Returns:

```json
{
    "visa_id": "ID"
}
```

