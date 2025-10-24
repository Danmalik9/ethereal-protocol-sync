;; Synchronizer Ledger Contract
;; Manages distributed synchronization entries with cryptographic anchoring
;; Users maintain immutable references to their synchronized content using Blake2B hashes

;; Error Code Definitions
(define-constant fail-unauthorized (err u100))
(define-constant fail-entry-not-found (err u101))
(define-constant fail-invalid-input (err u102))
(define-constant fail-entry-exists (err u103))
(define-constant fail-invalid-principal (err u104))

;; Data Storage Maps

;; Core synchronization entries indexed by unique sync-key
(define-map sync-entries
  { sync-key: (string-utf8 128) }
  {
    principal-owner: principal,
    content-hash: (buff 32),
    block-timestamp: uint,
    version-tag: (string-utf8 32),
    entry-metadata: (optional (string-utf8 256))
  }
)

;; Reverse index tracking all sync-keys owned by each principal
(define-map owner-sync-keys 
  { owner: principal }
  { keys: (list 100 (string-utf8 128)) }
)

;; Share grants tracking which principals have access permissions
(define-map share-grants
  { sync-key: (string-utf8 128), grantee: principal }
  { grant-write: bool }
)

;; Private Helper Functions

;; Checks if principal has write access to an entry (owner or granted)
(define-private (can-write-entry (sync-key (string-utf8 128)) (principal-caller principal))
  (let (
    (entry-ref (map-get? sync-entries { sync-key: sync-key }))
  )
    (if (is-some entry-ref)
      (or
        (is-eq (get principal-owner (unwrap! entry-ref false)) principal-caller)
        (default-to false (get grant-write (map-get? share-grants { sync-key: sync-key, grantee: principal-caller })))
      )
      false
    )
  )
)

;; Adds sync-key to owner's tracking list
(define-private (index-sync-key (owner principal) (sync-key (string-utf8 128)))
  (let (
    (current-list (default-to { keys: (list) } (map-get? owner-sync-keys { owner: owner })))
    (appended-list (unwrap! (as-max-len? (append (get keys current-list) sync-key) u100) false))
  )
    (map-set owner-sync-keys { owner: owner } { keys: appended-list })
    true
  )
)

;; Read-Only Query Functions

;; Retrieves a single synchronization entry by its key
(define-read-only (fetch-entry (sync-key (string-utf8 128)))
  (match (map-get? sync-entries { sync-key: sync-key })
    entry (ok entry)
    fail-entry-not-found
  )
)

;; Checks access permissions for a principal on a sync entry
(define-read-only (is-accessible (sync-key (string-utf8 128)) (accessor principal))
  (let (
    (entry-ref (map-get? sync-entries { sync-key: sync-key }))
  )
    (if (is-some entry-ref)
      (ok (or
        (is-eq (get principal-owner (unwrap-panic entry-ref)) accessor)
        (is-some (map-get? share-grants { sync-key: sync-key, grantee: accessor }))
      ))
      fail-entry-not-found
    )
  )
)

;; Retrieves all sync-keys owned by a principal
(define-read-only (query-owner-entries (owner principal))
  (ok (get keys (default-to { keys: (list) } (map-get? owner-sync-keys { owner: owner }))))
)

;; Public State-Changing Functions

;; Registers and anchors a new synchronization entry on-chain
(define-public (register-entry
    (sync-key (string-utf8 128))
    (content-hash (buff 32))
    (version-tag (string-utf8 32))
    (entry-metadata (optional (string-utf8 256))))
  (let (
    (caller tx-sender)
    (existing-entry (map-get? sync-entries { sync-key: sync-key }))
  )
    (asserts! (is-none existing-entry) fail-entry-exists)
    
    (map-set sync-entries
      { sync-key: sync-key }
      {
        principal-owner: caller,
        content-hash: content-hash,
        block-timestamp: block-height,
        version-tag: version-tag,
        entry-metadata: entry-metadata
      }
    )
    
    (asserts! (index-sync-key caller sync-key) fail-invalid-input)
    
    (ok true)
  )
)

;; Updates an existing synchronization entry with new data
(define-public (update-entry
    (sync-key (string-utf8 128))
    (content-hash (buff 32))
    (version-tag (string-utf8 32))
    (entry-metadata (optional (string-utf8 256))))
  (let (
    (caller tx-sender)
    (entry-ref (map-get? sync-entries { sync-key: sync-key }))
  )
    (asserts! (is-some entry-ref) fail-entry-not-found)
    (asserts! (can-write-entry sync-key caller) fail-unauthorized)
    
    (map-set sync-entries
      { sync-key: sync-key }
      {
        principal-owner: (get principal-owner (unwrap-panic entry-ref)),
        content-hash: content-hash,
        block-timestamp: block-height,
        version-tag: version-tag,
        entry-metadata: entry-metadata
      }
    )
    
    (ok true)
  )
)

;; Grants write access to another principal for a synchronization entry
(define-public (grant-write-access (sync-key (string-utf8 128)) (grantee principal) (grant-write bool))
  (let (
    (caller tx-sender)
    (entry-ref (map-get? sync-entries { sync-key: sync-key }))
  )
    (asserts! (is-some entry-ref) fail-entry-not-found)
    (asserts! (is-eq (get principal-owner (unwrap-panic entry-ref)) caller) fail-unauthorized)
    (asserts! (not (is-eq grantee caller)) fail-invalid-principal)
    
    (map-set share-grants
      { sync-key: sync-key, grantee: grantee }
      { grant-write: grant-write }
    )
    
    (ok true)
  )
)

;; Revokes all access permissions for a principal on a synchronization entry
(define-public (revoke-write-access (sync-key (string-utf8 128)) (grantee principal))
  (let (
    (caller tx-sender)
    (entry-ref (map-get? sync-entries { sync-key: sync-key }))
  )
    (asserts! (is-some entry-ref) fail-entry-not-found)
    (asserts! (is-eq (get principal-owner (unwrap-panic entry-ref)) caller) fail-unauthorized)
    
    (map-delete share-grants { sync-key: sync-key, grantee: grantee })
    
    (ok true)
  )
)