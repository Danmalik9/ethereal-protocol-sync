;; Integrity Verifier Contract
;; Cryptographic verification layer for data synchronization with conflict resolution
;; Maintains audit trails and ensures consistency across distributed replicas

;; ========== Error Constants ==========
(define-constant err-forbidden (err u100))
(define-constant err-no-record (err u101))
(define-constant err-hash-invalid (err u102))
(define-constant err-hash-mismatch (err u103))
(define-constant err-conflict-present (err u104))
(define-constant err-no-conflict (err u105))
(define-constant err-resolution-invalid (err u106))
(define-constant err-not-owner (err u107))
(define-constant err-record-missing (err u108))
(define-constant err-device-unregistered (err u109))

;; ========== Data Structures ==========

;; Primary hash registry mapping principals and identifiers to current state
(define-map hash-registry
  { owner: principal, record-id: (string-utf8 36) }
  { current-hash: (buff 32), recorded-at: uint, originating-device: (string-utf8 36) }
)

;; Conflict tracking for divergent states
(define-map conflict-registry
  { owner: principal, record-id: (string-utf8 36) }
  {
    divergent-hashes: (list 10 {
      hash-value: (buff 32),
      originating-device: (string-utf8 36),
      recorded-at: uint
    }),
    conflict-status: bool
  }
)

;; Device enrollment tracking
(define-map enrolled-devices
  { owner: principal, device-id: (string-utf8 36) }
  { name: (string-utf8 64), pubkey: (buff 33), active-status: bool }
)

;; Audit log storage
(define-map audit-log
  { owner: principal, record-id: (string-utf8 36) }
  {
    event-chain: (list 20 {
      hash-value: (buff 32),
      recorded-at: uint,
      originating-device: (string-utf8 36),
      operation-type: (string-utf8 10)
    })
  }
)

;; ========== Private Functions ==========

;; Checks device is registered and active
(define-private (device-is-active (owner principal) (device-id (string-utf8 36)))
  (match (map-get? enrolled-devices { owner: owner, device-id: device-id })
    device-info (and (get active-status device-info) true)
    false
  )
)

;; Appends operation to audit log
(define-private (append-audit-event
                  (owner principal)
                  (record-id (string-utf8 36))
                  (hash-value (buff 32))
                  (device-id (string-utf8 36))
                  (operation-type (string-utf8 10)))
  (let ((block-time (unwrap-panic (get-block-info? time u0)))
        (existing-log (default-to
                      { event-chain: (list) }
                      (map-get? audit-log { owner: owner, record-id: record-id })))
        (new-event {
          hash-value: hash-value,
          recorded-at: block-time,
          originating-device: device-id,
          operation-type: operation-type
        })
        (expanded-chain (unwrap-panic
                        (as-max-len?
                         (append (get event-chain existing-log) new-event)
                         u20))))
    (map-set audit-log
             { owner: owner, record-id: record-id }
             { event-chain: expanded-chain })
    true
  )
)

;; Checks if conflict exists and is unresolved
(define-private (active-conflict-exists (owner principal) (record-id (string-utf8 36)))
  (match (map-get? conflict-registry { owner: owner, record-id: record-id })
    conflict-info (not (get conflict-status conflict-info))
    false
  )
)

;; Compares hash against registry
(define-private (verify-hash-match
                  (owner principal)
                  (record-id (string-utf8 36))
                  (test-hash (buff 32))
                  (test-proof (buff 128)))
  (match (map-get? hash-registry { owner: owner, record-id: record-id })
    registry-entry (if (is-eq (get current-hash registry-entry) test-hash)
                     (ok true)
                     err-hash-mismatch)
    err-record-missing
  )
)

;; ========== Read-Only Functions ==========

;; Retrieves current hash for a record
(define-read-only (query-current-hash (owner principal) (record-id (string-utf8 36)))
  (match (map-get? hash-registry { owner: owner, record-id: record-id })
    hash-entry (ok hash-entry)
    err-record-missing
  )
)

;; Retrieves full audit trail
(define-read-only (query-audit-trail (owner principal) (record-id (string-utf8 36)))
  (match (map-get? audit-log { owner: owner, record-id: record-id })
    log-entry (ok log-entry)
    (ok { event-chain: (list) })
  )
)

;; Queries all devices (requires external indexing)
(define-read-only (list-user-devices (owner principal))
  (ok true)
)

;; Checks if device is active
(define-read-only (check-device-status (owner principal) (device-id (string-utf8 36)))
  (match (map-get? enrolled-devices { owner: owner, device-id: device-id })
    device-info (ok (get active-status device-info))
    (ok false)
  )
)

;; ========== Public Functions ==========

;; Enroll a new device for the caller
(define-public (enroll-device
                 (device-id (string-utf8 36))
                 (name (string-utf8 64))
                 (pubkey (buff 33)))
  (begin
    (asserts! (is-eq tx-sender contract-caller) err-forbidden)
    (map-set enrolled-devices
             { owner: tx-sender, device-id: device-id }
             { name: name, pubkey: pubkey, active-status: true })
    (ok true)
  )
)

;; Deactivates a device
(define-public (deactivate-enrollment (device-id (string-utf8 36)))
  (begin
    (asserts! (is-eq tx-sender contract-caller) err-forbidden)
    (match (map-get? enrolled-devices { owner: tx-sender, device-id: device-id })
      device-info (begin
                   (map-set enrolled-devices
                            { owner: tx-sender, device-id: device-id }
                            (merge device-info { active-status: false }))
                   (ok true))
      err-device-unregistered
    )
  )
)

;; Verify data against registry
(define-public (perform-verification
                 (record-id (string-utf8 36))
                 (hash-value (buff 32))
                 (proof (buff 128)))
  (begin
    (verify-hash-match tx-sender record-id hash-value proof)
  )
)

;; Verify data for another owner
(define-public (perform-verification-delegated
                 (owner principal)
                 (record-id (string-utf8 36))
                 (hash-value (buff 32))
                 (proof (buff 128)))
  (begin
    (verify-hash-match owner record-id hash-value proof)
  )
)