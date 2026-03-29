# MWEB HTTP API

This document describes the lightweight public HTTP bridge exposed by `mwebd`.

Litescribe uses this surface for read-only MWEB sync data:

- bridge base URL: `https://api.litescribe.io/mweb`
- content type: `application/json`
- CORS: enabled for `GET`, `POST`, and `OPTIONS`

The bridge does not expose wallet secrets, scan keys, spend keys, or account mutation endpoints.

## Endpoints

### `GET /status`

Returns bridge health and sync status.

Example:

```http
GET /mweb/status
```

Response:

```json
{
  "available": true,
  "synced": true,
  "network": "mainnet",
  "message": "mwebd ready",
  "height": 2876543,
  "tipHeight": 2876543,
  "blockTime": 1774700000,
  "utxosHeight": 2876543
}
```

Fields:

- `available`: bridge responded successfully
- `synced`: `true` when the bridge header height and UTXO height match the chain tip
- `network`: active Litecoin network name
- `message`: human-readable status string
- `height`: current MWEB header height
- `tipHeight`: current chain tip height seen by the bridge
- `blockTime`: Unix timestamp of the current tip block
- `utxosHeight`: current MWEB UTXO set height

### `GET /outputs`

Returns paginated public MWEB outputs from the bridge's view of the active leafset.

Query parameters:

- `cursor`: optional leaf index to start scanning from. Default: `0`
- `limit`: optional page size. Default: `1000`, max: `5000`

Example:

```http
GET /mweb/outputs?cursor=0&limit=2
```

Response:

```json
{
  "outputs": [
    {
      "outputId": "8c2b...",
      "rawOutput": "0102...",
      "leafIndex": 123,
      "height": 2876500,
      "blockTime": 1774699000
    }
  ],
  "nextCursor": 124,
  "hasMore": true,
  "tipHeight": 2876543
}
```

Fields:

- `outputs`: page of public outputs
- `nextCursor`: cursor to use for the next page
- `hasMore`: `true` when more outputs remain after this page
- `tipHeight`: chain tip height at the time of the query

Each `outputs[]` entry includes:

- `outputId`: hex MWEB output id
- `rawOutput`: serialized raw MWEB output as hex
- `leafIndex`: bridge leaf index for this output
- `height`: block height where the output was observed
- `blockTime`: Unix timestamp for that block when available

### `GET /spent`

Checks whether one or more MWEB output ids are no longer present in the unspent set.

Query parameters:

- `output_id`: repeated query parameter for each output id to check

Example:

```http
GET /mweb/spent?output_id=8c2b...&output_id=9fd1...
```

Response:

```json
{
  "outputId": [
    "8c2b..."
  ]
}
```

Interpretation:

- returned `outputId` values were not found in the current unspent set
- that means they are either already spent or not yet confirmed into the bridge view
- an empty array means every requested output id is still present in the unspent set

If no `output_id` values are provided, the bridge returns:

```json
{
  "outputId": []
}
```

## Error format

Errors are returned as JSON with an `error` string.

Example:

```json
{
  "error": "invalid cursor"
}
```

Common status codes:

- `400`: invalid query parameter
- `405`: unsupported HTTP method
- `500`: bridge/internal error

## Notes

- This bridge is intentionally read-only.
- It is suitable for client-side MWEB scanning and spend-tracking workflows.
- Sensitive wallet operations should remain client-side or use the authenticated gRPC/FFI surface instead of this public bridge.
