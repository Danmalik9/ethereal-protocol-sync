;; Access Authority Contract
;; Implements distributed permission matrices and device authentication mechanisms
;; Enables fine-grained access control with role hierarchies and device enrollment

;; ========== Error Constants ==========
(define-constant error-not-authorized (err u1000))
(define-constant error-already-exists (err u1001))
(define-constant error-bad-role (err u1002))
(define-constant error-no-dataset (err u1003))
(define-constant error-not-owner (err u1004))
(define-constant error-protected-owner (err u1005))
(define-constant error-device-bad (err u1006))
(define-constant error-device-duplicate (err u1007))
(define-constant error-no-user (err u1008))

;; ========== Role Constants ==========
(define-constant ROLE-ADMIN u100)
(define-constant ROLE-EDITOR u200)
(define-constant ROLE-VIEWER u300)

;; ========== Data Maps ==========

;; Maps dataset identifiers to their controlling owner
(define-map dataset-controller
  { dataset-id: (string-utf8 36) }
  { controller: principal }
)

;; Stores role assignments per user per dataset
(define-map role-assignment
  { dataset-id: (string-utf8 36), user: principal }
  { assigned-role: uint }
)

;; Manages device enrollments with audit trail
(define-map device-enrollments
  { user: principal, device-id: (string-utf8 36) }
  { status: bool, label: (string-utf8 64), enrollment-time: uint }
)

;; Tracks enumeration of enrolled devices
(define-map device-enrollment-index
  { user: principal }
  { device-list: (list 20 (string-utf8 36)) }
)

;; ========== Private Functions ==========

;; Validates role value is within acceptable range
(define-private (validate-role (role-value uint))
  (or
    (is-eq role-value ROLE-ADMIN)
    (is-eq role-value ROLE-EDITOR)
    (is-eq role-value ROLE-VIEWER)
  )
)

;; Checks if principal satisfies minimum role requirement
(define-private (meets-role-requirement (principal-param principal) (dataset-id (string-utf8 36)) (min-role uint))
  (let (
    (principal-role (unwrap-panic (query-principal-role principal-param dataset-id)))
  )
    (>= min-role principal-role)
  )
)

;; ========== Read-Only Functions ==========

;; Queries the controller of a dataset
(define-read-only (get-dataset-controller (dataset-id (string-utf8 36)))
  (map-get? dataset-controller { dataset-id: dataset-id })
)

;; Checks if principal is the designated controller
(define-read-only (is-controller (principal-check principal) (dataset-id (string-utf8 36)))
  (let (
    (controller-data (map-get? dataset-controller { dataset-id: dataset-id }))
  )
    (if (is-some controller-data)
      (is-eq principal-check (get controller (unwrap-panic controller-data)))
      false
    )
  )
)

;; Queries the numeric role assigned to a principal
(define-read-only (query-principal-role (principal-param principal) (dataset-id (string-utf8 36)))
  (let (
    (assignment-data (map-get? role-assignment { dataset-id: dataset-id, user: principal-param }))
  )
    (if (is-some assignment-data)
      (ok (get assigned-role (unwrap-panic assignment-data)))
      (ok u0)
    )
  )
)

;; Checks device enrollment status
(define-read-only (is-device-enrolled (user principal) (device-id (string-utf8 36)))
  (match (map-get? device-enrollments { user: user, device-id: device-id })
    device-info (get status device-info)
    false
  )
)

;; Retrieves all enrolled devices for a user
(define-read-only (get-enrolled-devices (user principal))
  (match (map-get? device-enrollment-index { user: user })
    enrollment-data (ok (get device-list enrollment-data))
    (ok (list))
  )
)

;; ========== Public Functions ==========

;; Creates a new dataset with caller as controller
(define-public (create-dataset (dataset-id (string-utf8 36)))
  (let (
    (controller-info (map-get? dataset-controller { dataset-id: dataset-id }))
  )
    (if (is-some controller-info)
      error-already-exists
      (begin
        (map-set dataset-controller
          { dataset-id: dataset-id }
          { controller: tx-sender }
        )
        
        (map-set role-assignment
          { dataset-id: dataset-id, user: tx-sender }
          { assigned-role: ROLE-ADMIN }
        )
        
        (ok true)
      )
    )
  )
)

;; Removes a principal's access to a dataset
(define-public (remove-principal-access (dataset-id (string-utf8 36)) (principal-param principal))
  (if (not (is-controller tx-sender dataset-id))
    error-not-owner
    
    (if (is-controller principal-param dataset-id)
      error-protected-owner
      
      (begin
        (map-delete role-assignment
          { dataset-id: dataset-id, user: principal-param }
        )
        (ok true)
      )
    )
  )
)

;; Deactivates a device without removal
(define-public (deactivate-device (device-id (string-utf8 36)))
  (let (
    (device-info (map-get? device-enrollments { user: tx-sender, device-id: device-id }))
  )
    (if (is-none device-info)
      error-device-bad
      (begin
        (map-set device-enrollments
          { user: tx-sender, device-id: device-id }
          { status: false, 
            label: (get label (unwrap-panic device-info)), 
            enrollment-time: (unwrap-panic (get-block-info? time (- block-height u1))) }
        )
        (ok true)
      )
    )
  )
)

;; Updates device sync timestamp
(define-public (record-device-sync (device-id (string-utf8 36)))
  (let (
    (device-info (map-get? device-enrollments { user: tx-sender, device-id: device-id }))
  )
    (if (is-none device-info)
      error-device-bad
      (let (
        (device-data (unwrap-panic device-info))
      )
        (if (not (get status device-data))
          error-device-bad
          (begin
            (map-set device-enrollments
              { user: tx-sender, device-id: device-id }
              { status: true,
                label: (get label device-data),
                enrollment-time: (unwrap-panic (get-block-info? time (- block-height u1))) }
            )
            (ok true)
          )
        )
      )
    )
  )
)

;; Transfers dataset controller rights
(define-public (transfer-controller-rights (dataset-id (string-utf8 36)) (new-controller principal))
  (if (not (is-controller tx-sender dataset-id))
    error-not-owner
    
    (begin
      (map-set dataset-controller
        { dataset-id: dataset-id }
        { controller: new-controller }
      )
      
      (map-delete role-assignment
        { dataset-id: dataset-id, user: tx-sender }
      )
      
      (map-set role-assignment
        { dataset-id: dataset-id, user: new-controller }
        { assigned-role: ROLE-ADMIN }
      )
      
      (ok true)
    )
  )
)