;; Version Tracker Contract
;; Tracks content versions, synchronization timelines, and device-specific state
;; Enables reconstruction of complete history and multi-device coordination

;; ========== Error Constants ==========
(define-constant fail-unauthorized (err u100))
(define-constant fail-bad-device (err u101))
(define-constant fail-bad-content-id (err u102))
(define-constant fail-bad-version (err u103))
(define-constant fail-bad-timestamp (err u104))
(define-constant fail-version-exists (err u105))
(define-constant fail-device-exists (err u106))
(define-constant fail-device-missing (err u107))
(define-constant fail-content-missing (err u108))
(define-constant fail-version-missing (err u109))

;; ========== Data Maps ==========

;; Device registry per user
(define-map user-device-registry
  { owner: principal }
  { devices: (list 100 { device-id: (string-utf8 36), device-name: (string-utf8 64), registered-at: uint }) }
)

;; Content metadata
(define-map content-metadata-store
  { content-id: (string-utf8 36), owner: principal }
  {
    name: (string-utf8 128),
    kind: (string-utf8 32),
    created-at: uint,
    updated-at: uint,
    byte-size: uint,
    current-version: uint
  }
)

;; Version history per content
(define-map version-history
  { content-id: (string-utf8 36), version-num: uint }
  {
    content-hash: (buff 32),
    version-time: uint,
    source-device: (string-utf8 36),
    change-notes: (string-utf8 256),
    byte-size: uint
  }
)

;; Per-device sync status
(define-map device-sync-checkpoint
  { content-id: (string-utf8 36), device-id: (string-utf8 36) }
  {
    synced-version: uint,
    checkpoint-time: uint
  }
)

;; ========== Private Functions ==========

;; Checks if user owns the content
(define-private (user-owns-content (content-id (string-utf8 36)) (user principal))
  (match (map-get? content-metadata-store { content-id: content-id, owner: user })
    item true
    false
  )
)

;; Gets latest version number
(define-private (fetch-current-version (content-id (string-utf8 36)) (user principal))
  (match (map-get? content-metadata-store { content-id: content-id, owner: user })
    metadata (get current-version metadata)
    u0
  )
)

;; ========== Read-Only Functions ==========

;; Returns all devices for a user
(define-read-only (fetch-user-devices (user principal))
  (default-to { devices: (list) } (map-get? user-device-registry { owner: user }))
)

;; Returns content metadata
(define-read-only (fetch-content-metadata (content-id (string-utf8 36)) (owner principal))
  (map-get? content-metadata-store { content-id: content-id, owner: owner })
)

;; Returns specific version details
(define-read-only (fetch-version-data (content-id (string-utf8 36)) (version-num uint))
  (map-get? version-history { content-id: content-id, version-num: version-num })
)

;; Returns sync checkpoint for a device
(define-read-only (fetch-sync-checkpoint (content-id (string-utf8 36)) (device-id (string-utf8 36)))
  (map-get? device-sync-checkpoint { content-id: content-id, device-id: device-id })
)

;; Checks if content exists
(define-read-only (exists-content (content-id (string-utf8 36)) (owner principal))
  (is-some (map-get? content-metadata-store { content-id: content-id, owner: owner }))
)

;; ========== Public Functions ==========

;; Creates content with initial metadata
(define-public (initialize-content
    (content-id (string-utf8 36))
    (name (string-utf8 128))
    (kind (string-utf8 32))
    (byte-size uint))
  (let
    (
      (caller tx-sender)
      (block-time (unwrap-panic (get-block-info? time (- block-height u1))))
    )
    (asserts! (not (exists-content content-id caller)) fail-content-missing)
    
    (map-set content-metadata-store
      { content-id: content-id, owner: caller }
      {
        name: name,
        kind: kind,
        created-at: block-time,
        updated-at: block-time,
        byte-size: byte-size,
        current-version: u1
      }
    )
    
    (ok true)
  )
)