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
| GET | `/admin/actors` | list connected actors |
| GET | `/admin/actors?role=node` | list connected nodes |
| GET | `/admin/actors/{CN}` | get actor with CN |
| DELETE | `/admin/actors/{CN}` | revoke an actor (and all its visas) by adapter CN |
| GET | `/admin/actors/{CN}/visas` | get visa ids related to actor with CN |
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

Returns:

```json
{
    "cns": ["CN"],
}

```

## List nodes `GET /admin/actors?role=node`

Returns:

```json

{
    "cns": ["CN"],
}

```

## Get actor `GET /admin/actors/{ID}`

Used to get both actors and nodes, since nodes are a special type of actors

Returns:

```json
{
    "cn": "CN",
    "ctime": CTIME_S,
    "ident": "IDENT",
    "node": NODE_BOOL,
    "zpr_addr": "ADDR",
    "node_details": {
        "connect_requests": REQS
        "in_sync": SYNC_BOOL,
        "last_contact": CONTACT,
        "pending": PENDING,
        "visa_requests": REQS,
    },
}
```

## Revoke actor `DELETE /admin/actors/{CN}`

Returns:

```json
{
    "identifier": "IDEN",
    "revoked_visas": ["ID1", "ID2", "..."]
}
```

## Visa IDs by actor `GET /admin/actors/{CN}/visas`

Returns:

```json
{
    "ids": ["ID"]
}
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

