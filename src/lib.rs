//! tabeliao — publisher-side companion to cartorio + lacre.
//!
//! Operator workflow:
//!
//! ```text
//!   manifest.json + attestations.yaml
//!         ↓
//!     [tabeliao publish]
//!         ↓
//!   1. compute sha256(manifest.json) = digest
//!   2. construct AdmitArtifactInput from attestations.yaml + digest
//!   3. compute state_leaf root = compose_state_leaf_root(...)
//!   4. sign root → SignedRoot (placeholder HMAC for v0.1; future:
//!      real Akeyless DFC or local-keyed)
//!   5. POST cartorio/api/v1/artifacts                           ← admit
//!   6. PUT  lacre/v2/<image>/manifests/<reference>              ← ship
//!         ↓
//!   image is now compliant + verifiable + in the registry.
//! ```
//!
//! Same digest flows through both submissions, so cartorio and lacre
//! agree on the artifact's identity by construction.

pub mod admit;
pub mod attestations;
pub mod error;
pub mod publish;
pub mod sign;

pub use admit::build_admit_input;
pub use attestations::AttestationsConfig;
pub use error::{Result, TabeliaoError};
pub use publish::{PublishOutcome, PublishPlan, publish};
